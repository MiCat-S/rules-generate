package output

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Yuu518/rules-generate/internal/model"
	"github.com/Yuu518/rules-generate/internal/trie"
)

const surgeRuleExt = ".list"

func ExportSurge(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "surge", splitByFormat)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	targets := filterLists(ruleMap, lists)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for code, rules := range targets {
		wg.Add(1)
		go func(code string, rules []model.DomainRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := saveSurgeRuleSet(rules, filepath.Join(dir, code+surgeRuleExt)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("surge export errors: %v", errors)
	}
	return nil
}

func ExportSurgeIP(ipRuleMap model.IPRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "surge", splitByFormat)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	targets := filterIPLists(ipRuleMap, lists)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for code, cidrs := range targets {
		wg.Add(1)
		go func(code string, cidrs []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := saveSurgeIPRuleSet(cidrs, filepath.Join(dir, code+surgeRuleExt)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, cidrs)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("surge ip export errors: %v", errors)
	}
	return nil
}

func saveSurgeRuleSet(rules []model.DomainRule, outputPath string) error {
	var lines ruleLines
	for _, rule := range filterSurgeCandidates(surgeCandidates(rules)) {
		lines.add(rule.Type, rule.Value, surgeRulePrefix(rule.Type)+","+rule.Value)
	}

	output := strings.Join(lines.sorted(), "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(outputPath, []byte(output), 0644)
}

func surgeRulePrefix(rank model.DomainType) string {
	switch rank {
	case model.DomainSuffix:
		return "DOMAIN-SUFFIX"
	case model.DomainKeyword:
		return "DOMAIN-KEYWORD"
	default:
		return "DOMAIN"
	}
}

func surgeCandidates(rules []model.DomainRule) []model.DomainRule {
	candidates := make([]model.DomainRule, 0, len(rules))
	for _, rule := range rules {
		switch rule.Type {
		case model.DomainFull, model.DomainSuffix, model.DomainKeyword:
			candidates = append(candidates, rule)
		}
	}
	return candidates
}

func filterSurgeCandidates(candidates []model.DomainRule) []model.DomainRule {
	drop := make([]bool, len(candidates))

	var suffixes []int
	for i, candidate := range candidates {
		if candidate.Type == model.DomainSuffix && !isTopLevel(candidate.Value) {
			suffixes = append(suffixes, i)
		}
	}
	sort.SliceStable(suffixes, func(i, j int) bool {
		return labelCount(candidates[suffixes[i]].Value) < labelCount(candidates[suffixes[j]].Value)
	})

	t := trie.NewDomainTrie()
	for _, i := range suffixes {
		success, err := t.Insert(candidates[i].Value)
		if err != nil || !success {
			drop[i] = true
		}
	}

	kept := make([]model.DomainRule, 0, len(candidates))
	for i, candidate := range candidates {
		if drop[i] {
			continue
		}
		if candidate.Type == model.DomainFull && t.Covers(candidate.Value) {
			continue
		}
		kept = append(kept, candidate)
	}

	return kept
}

func saveSurgeIPRuleSet(cidrs []string, outputPath string) error {
	var lines []string

	for _, cidr := range cidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			ip = net.ParseIP(cidr)
		}
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			lines = append(lines, "IP-CIDR,"+cidr)
		} else {
			lines = append(lines, "IP-CIDR6,"+cidr)
		}
	}

	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(outputPath, []byte(output), 0644)
}
