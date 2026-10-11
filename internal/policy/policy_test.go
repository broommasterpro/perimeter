package policy

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func examplePolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Load("../../policy.json")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writePolicy(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluate(t *testing.T) {
	p := examplePolicy(t)
	for _, tc := range []struct {
		name, group, app string
		posture          Posture
		want             Decision
	}{
		{"finance payroll", "finance", "payroll", Posture{true, true}, Decision{true, "allowed"}},
		{"missing disk", "finance", "payroll", Posture{false, true}, Decision{Reason: "missing posture: disk_encrypted"}},
		{"missing firewall", "finance", "payroll", Posture{true, false}, Decision{Reason: "missing posture: firewall_on"}},
		{"wrong group", "engineering", "payroll", Posture{true, true}, Decision{Reason: "group not allowed"}},
		{"deploy", "engineering", "deploy", Posture{true, false}, Decision{true, "allowed"}},
		{"deploy no disk", "engineering", "deploy", Posture{}, Decision{Reason: "missing posture: disk_encrypted"}},
		{"unknown", "finance", "hr2", Posture{}, Decision{Reason: "unknown app"}},
		{"absent posture", "finance", "payroll", Posture{}, Decision{Reason: "missing posture: disk_encrypted"}},
		{"wiki absent posture", "finance", "wiki", Posture{}, Decision{true, "allowed"}},
		{"case sensitive", "Finance", "wiki", Posture{}, Decision{Reason: "group not allowed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Evaluate(Request{User: "aisha", Group: tc.group, App: tc.app, Posture: tc.posture})
			if got != tc.want {
				t.Fatalf("got %+v; want %+v", got, tc.want)
			}
		})
	}
	empty, err := Parse([]byte(`{"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Evaluate(Request{App: "wiki", Group: "finance"}).Allow {
		t.Fatal("empty policy allowed")
	}
	var unavailable *Policy
	if unavailable.Evaluate(Request{}).Allow {
		t.Fatal("nil policy allowed")
	}
}

func TestParseRejects(t *testing.T) {
	for name, data := range map[string]string{
		"unknown field":      `{"rules":[],"typo":true}`,
		"unknown rule field": `{"rules":[{"app":"a","groups":["g"],"typo":true}]}`,
		"empty app":          `{"rules":[{"app":"","groups":["g"]}]}`,
		"empty groups":       `{"rules":[{"app":"a","groups":[]}]}`,
		"empty group":        `{"rules":[{"app":"a","groups":[""]}]}`,
		"unknown posture":    `{"rules":[{"app":"a","groups":["g"],"require":{"disk_encryptd":true}}]}`,
		"malformed":          `{`,
		"trailing JSON":      `{"rules":[]} {}`,
		"duplicate":          `{"rules":[{"app":"a","groups":["g","h"]},{"app":"a","groups":["h","g"],"require":{}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestAnyRuleAndOrder(t *testing.T) {
	a := `{"app":"payroll","groups":["finance"],"require":{"disk_encrypted":true}}`
	b := `{"app":"payroll","groups":["engineering"],"require":{}}`
	for _, rules := range []string{a + "," + b, b + "," + a} {
		p, err := Parse([]byte(`{"rules":[` + rules + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		if !p.Evaluate(Request{App: "payroll", Group: "engineering"}).Allow {
			t.Fatal("first rule shadowed matching rule")
		}
	}
}

func TestReload(t *testing.T) {
	store := NewStore(examplePolicy(t))
	request := Request{App: "wiki", Group: "finance"}
	if !store.Get().Evaluate(request).Allow {
		t.Fatal("initial policy denied")
	}
	path := t.TempDir() + "/policy.json"
	writePolicy(t, path, `{"rules":[]}`)
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	if store.Get().Evaluate(request).Allow {
		t.Fatal("reload did not revoke")
	}
	old := store.Get()
	writePolicy(t, path, `{"rules":[{"app":"wiki","groups":[]}]}`)
	if err := store.Reload(path); err == nil {
		t.Fatal("bad reload accepted")
	}
	if store.Get() != old {
		t.Fatal("bad reload replaced policy")
	}
	if err := store.Reload(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if store.Get() != old {
		t.Fatal("I/O error replaced policy")
	}
}

func TestConcurrentReload(t *testing.T) {
	store := NewStore(examplePolicy(t))
	dir := t.TempDir()
	allowPath, denyPath := dir+"/allow.json", dir+"/deny.json"
	writePolicy(t, allowPath, `{"rules":[{"app":"wiki","groups":["finance"]}]}`)
	writePolicy(t, denyPath, `{"rules":[]}`)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 2000; j++ {
				d := store.Get().Evaluate(Request{App: "wiki", Group: "finance"})
				if d.Reason != "allowed" && d.Reason != "unknown app" {
					t.Errorf("partial policy: %+v", d)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 100; i++ {
			for _, path := range []string{allowPath, denyPath} {
				if err := store.Reload(path); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	close(start)
	wg.Wait()
}

func TestDecisionTable(t *testing.T) {
	p := examplePolicy(t)
	for _, person := range []struct {
		name, group string
		posture     Posture
	}{
		{"aisha", "finance", Posture{true, true}},
		{"bob", "engineering", Posture{true, true}},
		{"carol", "finance", Posture{false, true}},
	} {
		var row []string
		for _, app := range []string{"payroll", "wiki", "deploy", "hr2"} {
			d := p.Evaluate(Request{User: person.name, Group: person.group, App: app, Posture: person.posture})
			row = append(row, app+"="+d.Reason)
		}
		t.Log(person.name + ": " + strings.Join(row, "; "))
	}
}
