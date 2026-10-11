// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

//go:embed assets/*.json
var ruleAssets embed.FS

type Rule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
}
type RuleSource struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type RuleBundle struct {
	Version   int          `json:"version"`
	UpdatedAt string       `json:"updated_at"`
	Sources   []RuleSource `json:"sources"`
	RUIP      []Rule       `json:"ru_ip"`
	RUDomains []Rule       `json:"ru_domains"`
}

func LoadRules(path string) (RuleBundle, error) {
	var b []byte
	var e error
	if path == "" {
		b, e = ruleAssets.ReadFile("assets/rules.json")
	} else {
		b, e = os.ReadFile(path)
	}
	var r RuleBundle
	if e != nil {
		return r, e
	}
	if e = DecodeStrict(b, &r); e != nil {
		return r, e
	}
	return r, r.Validate()
}
func (b RuleBundle) Validate() error {
	if b.Version != 1 || len(b.RUIP) == 0 || len(b.RUDomains) == 0 {
		return errors.New("invalid or empty RU rule bundle")
	}
	for _, r := range b.RUIP {
		if len(r.IPCIDR) == 0 || len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.DomainRegex) != 0 {
			return errors.New("RU IP rules must contain only ip_cidr")
		}
		for _, p := range r.IPCIDR {
			if _, e := netip.ParsePrefix(p); e != nil {
				return e
			}
		}
	}
	for _, r := range b.RUDomains {
		if len(r.IPCIDR) != 0 || len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.DomainRegex) == 0 {
			return errors.New("invalid RU domain rule")
		}
		for _, p := range r.DomainRegex {
			if _, e := regexp.Compile(p); e != nil {
				return e
			}
		}
		for _, list := range [][]string{r.Domain, r.DomainSuffix, r.DomainKeyword} {
			for _, s := range list {
				if s == "" {
					return errors.New("empty domain rule")
				}
			}
		}
	}
	return nil
}

const rulesBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/"

// UpdateRules downloads both sets before atomically replacing one complete bundle.
func UpdateRules(ctx context.Context, path string) error {
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 3 {
			return errors.New("unsafe rule redirect")
		}
		return nil
	}}
	return updateRules(ctx, path, client, rulesBase)
}
func updateRules(ctx context.Context, path string, client *http.Client, base string) error {
	b := RuleBundle{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, item := range []struct {
		path string
		into *[]Rule
	}{{"geoip/ru.json", &b.RUIP}, {"geosite/category-ru.json", &b.RUDomains}} {
		u := base + item.path
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if e != nil {
			return e
		}
		res, e := client.Do(req)
		if e != nil {
			return e
		}
		data, e := io.ReadAll(io.LimitReader(res.Body, (16<<20)+1))
		res.Body.Close()
		if e != nil {
			return e
		}
		if res.StatusCode != 200 || len(data) > 16<<20 {
			return fmt.Errorf("rule download failed: HTTP %d or size limit", res.StatusCode)
		}
		var source struct {
			Version int    `json:"version"`
			Rules   []Rule `json:"rules"`
		}
		if e = DecodeStrict(data, &source); e != nil {
			return e
		}
		if source.Version < 1 || source.Version > 4 {
			return errors.New("unsupported source rule version")
		}
		*item.into = source.Rules
		sum := sha256.Sum256(data)
		b.Sources = append(b.Sources, RuleSource{URL: u, SHA256: hex.EncodeToString(sum[:])})
	}
	if e := b.Validate(); e != nil {
		return e
	}
	manual, e := ruleAssets.ReadFile("assets/manual-domains.json")
	if e != nil {
		return e
	}
	var domains []string
	if e = json.Unmarshal(manual, &domains); e != nil {
		return e
	}
	b.RUDomains = append(b.RUDomains, Rule{DomainSuffix: domains})
	if e = b.Validate(); e != nil {
		return e
	}
	return WriteJSON(path, b, false)
}
func WriteJSON(path string, value any, exclusive bool) error {
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	if exclusive {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(data)
		closeErr := f.Close()
		if e != nil {
			os.Remove(path)
			return e
		}
		return closeErr
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".vos-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, path)
}
