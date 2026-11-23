package output

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yuu518/rules-generate/internal/model"
)

var clientDirectories = []string{"surge", "loon", "shadowrocket", "mihomo", "quantumult-x", "sing-box"}

type ConversionReport struct {
	SourceRuleSets     int              `json:"source_rule_sets"`
	ConvertedRuleSets  int              `json:"converted_rule_sets"`
	Rules              int              `json:"rules"` // Source entries, including domain_regex.
	BinaryOnly         []string         `json:"binary_only"`
	Targets            []string         `json:"targets"`
	SkippedDomainRegex DomainRegexSkips `json:"skipped_domain_regex"`
}

type DomainRegexSkips struct {
	Targets  []string       `json:"targets"`
	RuleSets map[string]int `json:"rule_sets"`
}

func ExportConverted(ruleSets model.SourceRuleSetMap, outputDir, quantumultPolicy string) (ConversionReport, error) {
	if quantumultPolicy == "" {
		quantumultPolicy = "proxy"
	}
	if err := prepareClientDirectories(outputDir); err != nil {
		return ConversionReport{}, err
	}

	keys := make([]string, 0, len(ruleSets))
	for key := range ruleSets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	report := ConversionReport{
		SourceRuleSets: len(keys),
		Targets:        append([]string(nil), clientDirectories...),
		SkippedDomainRegex: DomainRegexSkips{
			Targets:  []string{"surge", "loon", "shadowrocket", "quantumult-x"},
			RuleSets: make(map[string]int),
		},
	}

	for _, name := range keys {
		ruleSet := ruleSets[name]
		if len(ruleSet.DomainRegex) > 0 {
			report.SkippedDomainRegex.RuleSets[name] = len(ruleSet.DomainRegex)
		}
		if ruleSet.SourceJSONPath == "" {
			report.BinaryOnly = append(report.BinaryOnly, name)
		} else {
			report.ConvertedRuleSets++
		}
		report.Rules += len(ruleSet.Domains) + len(ruleSet.IPCIDR) + len(ruleSet.DomainRegex)

		if err := copyIfPresent(ruleSet.SourceJSONPath, filepath.Join(outputDir, "sing-box", name+".json")); err != nil {
			return ConversionReport{}, err
		}
		if err := copyIfPresent(ruleSet.SourceSRSPath, filepath.Join(outputDir, "sing-box", name+".srs")); err != nil {
			return ConversionReport{}, err
		}
		classical := classicalLines(ruleSet)
		if len(classical) > 0 {
			for _, target := range []string{"surge", "loon", "shadowrocket"} {
				if err := writeLines(filepath.Join(outputDir, target, name+".list"), classical); err != nil {
					return ConversionReport{}, err
				}
			}
			if err := writeLines(
				filepath.Join(outputDir, "quantumult-x", name+".list"),
				quantumultXLines(ruleSet, quantumultPolicy),
			); err != nil {
				return ConversionReport{}, err
			}
		}
		for _, pattern := range ruleSet.DomainRegex {
			classical = append(classical, "DOMAIN-REGEX,"+pattern)
		}
		if len(classical) > 0 {
			if err := saveMihomoYAML(classical, filepath.Join(outputDir, "mihomo", name+".yaml")); err != nil {
				return ConversionReport{}, err
			}
		}
	}
	return report, nil
}

func WriteConversionReport(report ConversionReport, path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func prepareClientDirectories(outputDir string) error {
	for _, target := range clientDirectories {
		directory := filepath.Join(outputDir, target)
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "site-") && !strings.HasPrefix(entry.Name(), "ip-") {
				continue
			}
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func classicalLines(ruleSet *model.SourceRuleSet) []string {
	var lines ruleLines
	for _, rule := range ruleSet.Domains {
		var prefix string
		switch rule.Type {
		case model.DomainFull:
			prefix = "DOMAIN"
		case model.DomainSuffix:
			prefix = "DOMAIN-SUFFIX"
		case model.DomainKeyword:
			prefix = "DOMAIN-KEYWORD"
		default:
			continue
		}
		lines.add(rule.Type, rule.Value, prefix+","+rule.Value)
	}
	result := lines.sorted()
	for _, cidr := range ruleSet.IPCIDR {
		prefix := "IP-CIDR6"
		if ip, _, _ := net.ParseCIDR(cidr); ip != nil && ip.To4() != nil {
			prefix = "IP-CIDR"
		}
		result = append(result, prefix+","+cidr)
	}
	return result
}

func quantumultXLines(ruleSet *model.SourceRuleSet, policy string) []string {
	lines := make([]string, 0, len(ruleSet.Domains)+len(ruleSet.IPCIDR))
	for _, rule := range ruleSet.Domains {
		var prefix string
		switch rule.Type {
		case model.DomainFull:
			prefix = "host"
		case model.DomainSuffix:
			prefix = "host-suffix"
		case model.DomainKeyword:
			prefix = "host-keyword"
		default:
			continue
		}
		lines = append(lines, prefix+","+rule.Value+","+policy)
	}
	for _, cidr := range ruleSet.IPCIDR {
		prefix := "ip6-cidr"
		if ip, _, _ := net.ParseCIDR(cidr); ip != nil && ip.To4() != nil {
			prefix = "ip-cidr"
		}
		lines = append(lines, prefix+","+cidr+","+policy)
	}
	return lines
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func copyIfPresent(source, destination string) error {
	if source == "" {
		return nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0644)
}
