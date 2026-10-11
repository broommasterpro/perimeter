package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

var benchmarkDecision Decision

func benchmarkRules(b *testing.B) (*Policy, []rule) {
	b.Helper()
	rules := make([]rule, 10000)
	for i := range rules {
		rules[i] = rule{App: fmt.Sprintf("app-%05d", i), Groups: []string{"finance"}, Require: Posture{DiskEncrypted: true}}
	}
	data, err := json.Marshal(struct {
		Rules []rule `json:"rules"`
	}{rules})
	if err != nil {
		b.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		b.Fatal(err)
	}
	return p, rules
}

func naiveEvaluate(rules []rule, r Request) Decision {
	for _, rule := range rules {
		if rule.App == r.App && slices.Contains(rule.Groups, r.Group) &&
			(!rule.Require.DiskEncrypted || r.Posture.DiskEncrypted) &&
			(!rule.Require.FirewallOn || r.Posture.FirewallOn) {
			return Decision{Allow: true, Reason: "allowed"}
		}
	}
	return Decision{Reason: "denied"}
}

func benchmarkEvaluate(b *testing.B, allow, naive bool) {
	p, rules := benchmarkRules(b)
	r := Request{App: "app-09999", Group: "finance", Posture: Posture{DiskEncrypted: allow}}
	b.ReportAllocs()
	b.ResetTimer()
	if naive {
		for i := 0; i < b.N; i++ {
			benchmarkDecision = naiveEvaluate(rules, r)
		}
	} else {
		for i := 0; i < b.N; i++ {
			benchmarkDecision = p.Evaluate(r)
		}
	}
}

func BenchmarkEvaluateAllow(b *testing.B) { benchmarkEvaluate(b, true, false) }
func BenchmarkEvaluateDeny(b *testing.B)  { benchmarkEvaluate(b, false, false) }
func BenchmarkNaiveAllow(b *testing.B)    { benchmarkEvaluate(b, true, true) }
func BenchmarkNaiveDeny(b *testing.B)     { benchmarkEvaluate(b, false, true) }
