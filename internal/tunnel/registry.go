package tunnel

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"perimeter/internal/mux"
)

type Registry struct {
	apps map[string][]string
	ids  map[string]bool
}

func ParseRegistry(data []byte) (*Registry, error) {
	var doc struct {
		Connectors []struct {
			ID   string   `json:"id"`
			Apps []string `json:"apps"`
		} `json:"connectors"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("trailing registry JSON")
	}
	r := &Registry{apps: make(map[string][]string), ids: make(map[string]bool)}
	for _, c := range doc.Connectors {
		if strings.TrimSpace(c.ID) == "" || r.ids[c.ID] {
			return nil, errors.New("empty or duplicate connector ID")
		}
		r.ids[c.ID] = true
		seen := make(map[string]bool)
		for _, app := range c.Apps {
			if !mux.ValidApp(app) || seen[app] {
				return nil, errors.New("invalid or duplicate app")
			}
			seen[app] = true
			r.apps[app] = append(r.apps[app], c.ID)
		}
	}
	return r, nil
}
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRegistry(data)
}

func HasConnectorRole(cert *x509.Certificate) bool {
	for _, uri := range cert.URIs {
		if uri.Scheme == "perimeter" && uri.Host == "connector" {
			return true
		}
	}
	return false
}
func ConnectorID(cert *x509.Certificate) (string, error) {
	id := ""
	for _, uri := range cert.URIs {
		if uri.Scheme == "perimeter" && uri.Host == "connector" {
			if id != "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.Path != "/"+cert.Subject.CommonName {
				return "", errors.New("invalid connector role")
			}
			id = cert.Subject.CommonName
		}
	}
	if id == "" {
		return "", errors.New("connector role required")
	}
	return id, nil
}
