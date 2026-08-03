package output

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Yuu518/rules-generate/internal/model"
)

const textRuleExt = ".txt"

func ExportText(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "text", splitByFormat)
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

			if err := saveTextRuleSet(rules, filepath.Join(dir, code+textRuleExt)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("text export errors: %v", errors)
	}
	return nil
}

func ExportTextIP(ipRuleMap model.IPRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "text", splitByFormat)
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

			if err := saveTextIPRuleSet(cidrs, filepath.Join(dir, code+textRuleExt)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, cidrs)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("text ip export errors: %v", errors)
	}
	return nil
}

func saveTextRuleSet(rules []model.DomainRule, outputPath string) error {
	var lines ruleLines

	for _, rule := range rules {
		switch rule.Type {
		case model.DomainFull:
			lines.add(model.DomainFull, rule.Value, "full:"+rule.Value)
		case model.DomainSuffix:
			lines.add(model.DomainSuffix, rule.Value, "domain:"+rule.Value)
		case model.DomainKeyword:
			lines.add(model.DomainKeyword, rule.Value, "keyword:"+rule.Value)
		case model.DomainRegexp:
			lines.add(model.DomainRegexp, rule.Value, "regexp:"+rule.Value)
		}
	}

	output := strings.Join(lines.sorted(), "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(outputPath, []byte(output), 0644)
}

func saveTextIPRuleSet(cidrs []string, outputPath string) error {
	var lines []string

	for _, cidr := range cidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			ip = net.ParseIP(cidr)
		}
		if ip == nil {
			continue
		}
		lines = append(lines, cidr)
	}

	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(outputPath, []byte(output), 0644)
}
