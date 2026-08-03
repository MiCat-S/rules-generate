package output

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yuu518/rules-generate/internal/model"
)

func isTopLevel(value string) bool {
	return !strings.Contains(value, ".")
}

func labelCount(value string) int {
	return strings.Count(value, ".") + 1
}

type ruleLineEntry struct {
	rank model.DomainType
	key  string
	text string
}

type ruleLines struct {
	entries []ruleLineEntry
}

func (r *ruleLines) add(rank model.DomainType, key, text string) {
	r.entries = append(r.entries, ruleLineEntry{rank: rank, key: key, text: text})
}

func (r *ruleLines) len() int {
	return len(r.entries)
}

func (r *ruleLines) sorted() []string {
	sort.Slice(r.entries, func(i, j int) bool {
		a, b := r.entries[i], r.entries[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.key != b.key {
			return a.key < b.key
		}
		return a.text < b.text
	})

	lines := make([]string, 0, len(r.entries))
	for _, entry := range r.entries {
		if len(lines) > 0 && lines[len(lines)-1] == entry.text {
			continue
		}
		lines = append(lines, entry.text)
	}
	return lines
}

func formatOutputDir(outputDir, format string, splitByFormat bool) string {
	if splitByFormat {
		return filepath.Join(outputDir, format)
	}
	return outputDir
}

func filterLists(ruleMap model.RuleMap, lists []string) model.RuleMap {
	if len(lists) == 0 {
		return ruleMap
	}

	wanted := make(map[string]bool)
	for _, l := range lists {
		wanted[strings.ToLower(strings.TrimSpace(l))] = true
	}

	result := make(model.RuleMap)
	for code, rules := range ruleMap {
		baseName := code
		if idx := strings.Index(code, "@"); idx >= 0 {
			baseName = code[:idx]
		}
		if wanted[code] || wanted[baseName] {
			result[code] = rules
		}
	}
	return result
}

func filterAdGuardLists(ruleMap model.AdGuardRuleMap, lists []string) model.AdGuardRuleMap {
	if len(lists) == 0 {
		return ruleMap
	}

	wanted := make(map[string]bool)
	for _, l := range lists {
		wanted[strings.ToLower(strings.TrimSpace(l))] = true
	}

	result := make(model.AdGuardRuleMap)
	for code, rules := range ruleMap {
		if wanted[code] {
			result[code] = rules
		}
	}
	return result
}

func filterIPLists(ipRuleMap model.IPRuleMap, lists []string) model.IPRuleMap {
	if len(lists) == 0 {
		return ipRuleMap
	}

	wanted := make(map[string]bool)
	for _, l := range lists {
		wanted[strings.ToLower(strings.TrimSpace(l))] = true
	}

	result := make(model.IPRuleMap)
	for code, cidrs := range ipRuleMap {
		if wanted[code] {
			result[code] = cidrs
		}
	}
	return result
}
