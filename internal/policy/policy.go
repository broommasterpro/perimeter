package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type Posture struct {
	DiskEncrypted bool `json:"disk_encrypted"`
	FirewallOn    bool `json:"firewall_on"`
}

type Request struct {
	User, Group, App string
	Posture          Posture
}

type Decision struct {
	Allow  bool
	Reason string
}

type rule struct {
	App     string   `json:"app"`
	Groups  []string `json:"groups"`
	Require Posture  `json:"require"`
}

type Policy struct {
	byApp map[string][]rule
}

func Parse(data []byte) (*Policy, error) {
	var document struct {
		Rules []rule `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	// A misspelled requirement must not silently become optional.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("multiple JSON values")
	}
	p := &Policy{byApp: make(map[string][]rule)}
	seen := make(map[string]bool)
	for i, r := range document.Rules {
		if err := validate(r); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		slices.Sort(r.Groups)
		r.Groups = slices.Compact(r.Groups)
		canonical, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if seen[string(canonical)] {
			return nil, fmt.Errorf("rule %d: duplicate rule", i+1)
		}
		seen[string(canonical)] = true
		p.byApp[r.App] = append(p.byApp[r.App], r)
	}
	return p, nil
}

func validate(r rule) error {
	if strings.TrimSpace(r.App) == "" {
		return errors.New("empty app")
	}
	if len(r.Groups) == 0 {
		return errors.New("empty groups")
	}
	for _, group := range r.Groups {
		if strings.TrimSpace(group) == "" {
			return errors.New("empty group")
		}
	}
	return nil
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (p *Policy) Evaluate(r Request) Decision {
	if p == nil {
		return Decision{Reason: "policy unavailable"}
	}
	rules, ok := p.byApp[r.App]
	if !ok {
		return Decision{Reason: "unknown app"}
	}
	groupMatched, missingDisk, missingFirewall := false, false, false
	for _, rule := range rules {
		if !slices.Contains(rule.Groups, r.Group) {
			continue
		}
		groupMatched = true
		disk := rule.Require.DiskEncrypted && !r.Posture.DiskEncrypted
		firewall := rule.Require.FirewallOn && !r.Posture.FirewallOn
		if !disk && !firewall {
			return Decision{Allow: true, Reason: "allowed"}
		}
		missingDisk = missingDisk || disk
		missingFirewall = missingFirewall || firewall
	}
	// Stable diagnostics do not depend on rule order; any matching rule allows.
	if !groupMatched {
		return Decision{Reason: "group not allowed"}
	}
	if missingDisk {
		return Decision{Reason: "missing posture: disk_encrypted"}
	}
	if missingFirewall {
		return Decision{Reason: "missing posture: firewall_on"}
	}
	return Decision{Reason: "policy evaluation failed"}
}
