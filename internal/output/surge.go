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
	"github.com/Yuu518/rules-generate/internal/regexrule"
	"github.com/Yuu518/rules-generate/internal/trie"
)

const surgeRuleExt = ".list"

type surgeRegexStats struct {
	converted int
	produced  int
	dropped   int
	skipped   int
}

type surgeCandidate struct {
	rank      model.DomainType
	value     string
	fromRegex bool
}

func ExportSurge(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool, wildcardRegex bool) error {
	dir := formatOutputDir(outputDir, "surge", splitByFormat)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	targets := filterLists(ruleMap, lists)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error
	var stats surgeRegexStats

	for code, rules := range targets {
		wg.Add(1)
		go func(code string, rules []model.DomainRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ruleStats, err := saveSurgeRuleSet(rules, filepath.Join(dir, code+surgeRuleExt), wildcardRegex)
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
			}
			stats.converted += ruleStats.converted
			stats.produced += ruleStats.produced
			stats.dropped += ruleStats.dropped
			stats.skipped += ruleStats.skipped
			mu.Unlock()
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("surge export errors: %v", errors)
	}

	if wildcardRegex && stats.converted+stats.skipped > 0 {
		fmt.Printf("Surge: converted %d regex rules into %d domain rules, dropped %d covered, skipped %d\n", stats.converted, stats.produced, stats.dropped, stats.skipped)
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

func saveSurgeRuleSet(rules []model.DomainRule, outputPath string, wildcardRegex bool) (surgeRegexStats, error) {
	candidates, stats := surgeCandidates(rules, wildcardRegex)
	kept, dropped := filterSurgeCandidates(candidates)
	stats.dropped = dropped

	var lines ruleLines
	for _, candidate := range kept {
		if candidate.fromRegex {
			stats.produced++
		}
		lines.add(candidate.rank, candidate.value, surgeRulePrefix(candidate.rank)+","+candidate.value)
	}

	output := strings.Join(lines.sorted(), "\n")
	if output != "" {
		output += "\n"
	}
	return stats, os.WriteFile(outputPath, []byte(output), 0644)
}

func surgeRulePrefix(rank model.DomainType) string {
	switch rank {
	case model.DomainFull:
		return "DOMAIN"
	case model.DomainSuffix:
		return "DOMAIN-SUFFIX"
	case model.DomainKeyword:
		return "DOMAIN-KEYWORD"
	default:
		return "DOMAIN-WILDCARD"
	}
}

func surgeCandidates(rules []model.DomainRule, wildcardRegex bool) ([]surgeCandidate, surgeRegexStats) {
	var candidates []surgeCandidate
	var stats surgeRegexStats

	for _, rule := range rules {
		switch rule.Type {
		case model.DomainFull, model.DomainSuffix, model.DomainKeyword:
			candidates = append(candidates, surgeCandidate{rank: rule.Type, value: rule.Value})
		case model.DomainRegexp:
			if !wildcardRegex {
				continue
			}
			converted, ok := regexrule.ToRules(rule.Value)
			if !ok {
				stats.skipped++
				continue
			}
			stats.converted++
			for _, converted := range converted {
				rank := model.DomainRegexp
				switch converted.Kind {
				case regexrule.KindFull:
					rank = model.DomainFull
				case regexrule.KindSuffix:
					rank = model.DomainSuffix
				}
				candidates = append(candidates, surgeCandidate{rank: rank, value: converted.Value, fromRegex: true})
			}
		}
	}

	return candidates, stats
}

func filterSurgeCandidates(candidates []surgeCandidate) ([]surgeCandidate, int) {
	drop := make([]bool, len(candidates))

	var suffixes []int
	for i, candidate := range candidates {
		if candidate.rank == model.DomainSuffix && !isTopLevel(candidate.value) {
			suffixes = append(suffixes, i)
		}
	}
	sort.SliceStable(suffixes, func(i, j int) bool {
		return labelCount(candidates[suffixes[i]].value) < labelCount(candidates[suffixes[j]].value)
	})

	t := trie.NewDomainTrie()
	for _, i := range suffixes {
		success, err := t.Insert(candidates[i].value)
		if err != nil || !success {
			drop[i] = true
		}
	}

	kept := make([]surgeCandidate, 0, len(candidates))
	dropped := 0
	for i, candidate := range candidates {
		if drop[i] {
			if candidate.fromRegex {
				dropped++
			}
			continue
		}
		switch candidate.rank {
		case model.DomainFull:
			if t.Covers(candidate.value) {
				if candidate.fromRegex {
					dropped++
				}
				continue
			}
		case model.DomainRegexp:
			if tail := wildcardTail(candidate.value); tail != "" && t.Covers(tail) {
				if candidate.fromRegex {
					dropped++
				}
				continue
			}
		}
		kept = append(kept, candidate)
	}

	return kept, dropped
}

func wildcardTail(pattern string) string {
	parts := strings.Split(pattern, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.ContainsAny(parts[i], "*?") {
			return strings.Join(parts[i+1:], ".")
		}
	}
	return pattern
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
