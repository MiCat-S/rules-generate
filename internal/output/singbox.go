package output

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Yuu518/rules-generate/internal/model"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
)

func ExportSingBox(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "singbox", splitByFormat)
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

			if err := saveSingBoxRuleSet(rules, filepath.Join(dir, code)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("sing-box export errors: %v", errors)
	}
	return nil
}

func ExportSingBoxIP(ipRuleMap model.IPRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "singbox", splitByFormat)
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

			if err := saveSingBoxIPRuleSet(cidrs, filepath.Join(dir, code)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, cidrs)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("sing-box ip export errors: %v", errors)
	}
	return nil
}

func ExportSingBoxAdGuard(ruleMap model.AdGuardRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	dir := formatOutputDir(outputDir, "singbox", splitByFormat)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	targets := filterAdGuardLists(ruleMap, lists)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for code, rules := range targets {
		wg.Add(1)
		go func(code string, rules []option.HeadlessRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := saveSingBoxAdGuardRuleSet(rules, filepath.Join(dir, code)); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", code, err))
				mu.Unlock()
			}
		}(code, rules)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("sing-box adguard export errors: %v", errors)
	}
	return nil
}

func ExportSingBoxAdGuardFile(ruleMap model.AdGuardRuleMap, outputPath string) error {
	if len(ruleMap) != 1 {
		return fmt.Errorf("output path %q is a single file but %d rule sets were parsed; use an output directory instead", outputPath, len(ruleMap))
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	for _, rules := range ruleMap {
		plainRuleSet := option.PlainRuleSetCompat{
			Version: C.RuleSetVersion2,
			Options: option.PlainRuleSet{
				Rules: rules,
			},
		}
		return saveSingBinaryRuleSet(&plainRuleSet, outputPath)
	}
	return nil
}

func saveSingBoxAdGuardRuleSet(rules []option.HeadlessRule, outputPath string) error {
	plainRuleSet := option.PlainRuleSetCompat{
		Version: C.RuleSetVersion2,
		Options: option.PlainRuleSet{
			Rules: rules,
		},
	}

	return saveSingBinaryRuleSet(&plainRuleSet, outputPath+".srs")
}

func saveSingBoxIPRuleSet(cidrs []string, outputPath string) error {
	headlessRule := option.DefaultHeadlessRule{
		IPCIDR: cidrs,
	}

	plainRuleSet := option.PlainRuleSetCompat{
		Version: C.RuleSetVersion2,
		Options: option.PlainRuleSet{
			Rules: common.Map([]option.DefaultHeadlessRule{headlessRule}, func(it option.DefaultHeadlessRule) option.HeadlessRule {
				return option.HeadlessRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: it,
				}
			}),
		},
	}

	if err := saveSingSourceRuleSet(&plainRuleSet, outputPath+".json"); err != nil {
		return err
	}

	return saveSingBinaryRuleSet(&plainRuleSet, outputPath+".srs")
}

func saveSingBoxRuleSet(rules []model.DomainRule, outputPath string) error {
	var domainFull, domainSuffix, domainKeyword, domainRegex []string

	for _, rule := range rules {
		switch rule.Type {
		case model.DomainFull:
			domainFull = append(domainFull, rule.Value)
		case model.DomainSuffix:
			domainSuffix = append(domainSuffix, rule.Value)
		case model.DomainKeyword:
			domainKeyword = append(domainKeyword, rule.Value)
		case model.DomainRegexp:
			domainRegex = append(domainRegex, rule.Value)
		}
	}

	sort.Strings(domainFull)
	sort.Strings(domainSuffix)
	sort.Strings(domainKeyword)
	sort.Strings(domainRegex)

	headlessRule := option.DefaultHeadlessRule{
		Domain:        domainFull,
		DomainSuffix:  domainSuffix,
		DomainKeyword: domainKeyword,
		DomainRegex:   domainRegex,
	}

	plainRuleSet := option.PlainRuleSetCompat{
		Version: C.RuleSetVersion2,
		Options: option.PlainRuleSet{
			Rules: common.Map([]option.DefaultHeadlessRule{headlessRule}, func(it option.DefaultHeadlessRule) option.HeadlessRule {
				return option.HeadlessRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: it,
				}
			}),
		},
	}

	if err := saveSingSourceRuleSet(&plainRuleSet, outputPath+".json"); err != nil {
		return err
	}

	if err := saveSingBinaryRuleSet(&plainRuleSet, outputPath+".srs"); err != nil {
		return err
	}

	return nil
}

func saveSingSourceRuleSet(ruleset *option.PlainRuleSetCompat, outputPath string) error {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(ruleset); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return os.WriteFile(outputPath, buffer.Bytes(), 0644)
}

func saveSingBinaryRuleSet(ruleset *option.PlainRuleSetCompat, outputPath string) error {
	ruleSet, err := ruleset.Upgrade()
	if err != nil {
		return err
	}
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	err = srs.Write(outputFile, ruleSet, C.RuleSetVersion2)
	if err != nil {
		outputFile.Close()
		os.Remove(outputPath)
		return err
	}
	outputFile.Close()
	return nil
}
