package output

import (
	"github.com/Yuu518/rules-generate/internal/model"
)

const loonRuleExt = ".lsr"

func ExportLoon(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	return exportTextRuleSet(ruleMap, formatOutputDir(outputDir, "loon", splitByFormat), lists, concurrency, loonRuleExt)
}

func ExportLoonIP(ipRuleMap model.IPRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	return exportTextIPRuleSet(ipRuleMap, formatOutputDir(outputDir, "loon", splitByFormat), lists, concurrency, loonRuleExt)
}
