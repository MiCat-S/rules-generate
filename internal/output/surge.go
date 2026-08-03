package output

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Yuu518/rules-generate/internal/model"
	"github.com/Yuu518/rules-generate/internal/regexrule"
)

const surgeRuleExt = ".list"

type surgeRegexStats struct {
	converted int
	produced  int
	skipped   int
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
			stats.skipped += ruleStats.skipped
			mu.Unlock()
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("surge export errors: %v", errors)
	}

	if wildcardRegex && stats.converted+stats.skipped > 0 {
		fmt.Printf("Surge: converted %d regex rules into %d domain rules, skipped %d\n", stats.converted, stats.produced, stats.skipped)
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
	var lines []string
	var stats surgeRegexStats

	for _, rule := range rules {
		switch rule.Type {
		case model.DomainFull:
			lines = append(lines, "DOMAIN,"+rule.Value)
		case model.DomainSuffix:
			lines = append(lines, "DOMAIN-SUFFIX,"+rule.Value)
		case model.DomainKeyword:
			lines = append(lines, "DOMAIN-KEYWORD,"+rule.Value)
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
			stats.produced += len(converted)
			for _, converted := range converted {
				switch converted.Kind {
				case regexrule.KindFull:
					lines = append(lines, "DOMAIN,"+converted.Value)
				case regexrule.KindSuffix:
					lines = append(lines, "DOMAIN-SUFFIX,"+converted.Value)
				default:
					lines = append(lines, "DOMAIN-WILDCARD,"+converted.Value)
				}
			}
		}
	}

	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n"
	}
	return stats, os.WriteFile(outputPath, []byte(output), 0644)
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
