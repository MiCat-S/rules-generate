package input

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yuu518/rules-generate/internal/model"
)

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			return fmt.Errorf("value must not be empty")
		}
		*s = []string{single}
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("expected string or string array: %w", err)
	}
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("value must not be empty")
		}
	}
	*s = values
	return nil
}

type singBoxSource struct {
	Version int                 `json:"version"`
	Rules   []singBoxSourceRule `json:"rules"`
}

type singBoxSourceRule struct {
	Domain        stringList `json:"domain,omitempty"`
	DomainSuffix  stringList `json:"domain_suffix,omitempty"`
	DomainKeyword stringList `json:"domain_keyword,omitempty"`
	DomainRegex   stringList `json:"domain_regex,omitempty"`
	IPCIDR        stringList `json:"ip_cidr,omitempty"`
}

func ParseSingBoxDir(root string) (model.SourceRuleSetMap, error) {
	result := make(model.SourceRuleSetMap)
	for _, directory := range []string{"rule_set_site", "rule_set_ip"} {
		base := filepath.Join(root, directory)
		if info, err := os.Stat(base); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("missing %s directory", directory)
		}

		var paths []string
		if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && (filepath.Ext(path) == ".json" || filepath.Ext(path) == ".srs") {
				paths = append(paths, path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		sort.Strings(paths)

		prefix := "site-"
		if directory == "rule_set_ip" {
			prefix = "ip-"
		}
		for _, path := range paths {
			relative, err := filepath.Rel(base, path)
			if err != nil {
				return nil, err
			}
			withoutExtension := strings.TrimSuffix(relative, filepath.Ext(relative))
			name := prefix + strings.ReplaceAll(filepath.ToSlash(withoutExtension), "/", "-")
			ruleSet := result[name]
			if ruleSet == nil {
				ruleSet = &model.SourceRuleSet{}
				result[name] = ruleSet
			}

			switch filepath.Ext(path) {
			case ".json":
				if ruleSet.SourceJSONPath != "" {
					return nil, fmt.Errorf("duplicate JSON output name %q", name)
				}
				if err := parseSingBoxSource(path, ruleSet); err != nil {
					return nil, err
				}
				ruleSet.SourceJSONPath = path
			case ".srs":
				if ruleSet.SourceSRSPath != "" {
					return nil, fmt.Errorf("duplicate SRS output name %q", name)
				}
				ruleSet.SourceSRSPath = path
			}
		}
	}
	return result, nil
}

func parseSingBoxSource(path string, target *model.SourceRuleSet) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var source singBoxSource
	if err := decoder.Decode(&source); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if source.Version <= 0 || source.Rules == nil {
		return fmt.Errorf("parse %s: version and rules are required", path)
	}

	for _, rule := range source.Rules {
		for _, value := range rule.Domain {
			target.Domains = append(target.Domains, model.DomainRule{Type: model.DomainFull, Value: value})
		}
		for _, value := range rule.DomainSuffix {
			target.Domains = append(target.Domains, model.DomainRule{Type: model.DomainSuffix, Value: strings.TrimPrefix(value, ".")})
		}
		for _, value := range rule.DomainKeyword {
			target.Domains = append(target.Domains, model.DomainRule{Type: model.DomainKeyword, Value: value})
		}
		target.DomainRegex = append(target.DomainRegex, rule.DomainRegex...)
		for _, value := range rule.IPCIDR {
			if ip, _, err := net.ParseCIDR(value); err != nil || ip == nil {
				return fmt.Errorf("parse %s: invalid CIDR %q", path, value)
			}
			target.IPCIDR = append(target.IPCIDR, value)
		}
	}
	return nil
}
