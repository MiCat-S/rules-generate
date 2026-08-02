package output

import (
	"github.com/Yuu518/rules-generate/internal/model"
)

const surgeRuleExt = ".list"

func ExportSurge(ruleMap model.RuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	return exportTextRuleSet(ruleMap, formatOutputDir(outputDir, "surge", splitByFormat), lists, concurrency, surgeRuleExt)
}

func ExportSurgeIP(ipRuleMap model.IPRuleMap, outputDir string, lists []string, concurrency int, splitByFormat bool) error {
	return exportTextIPRuleSet(ipRuleMap, formatOutputDir(outputDir, "surge", splitByFormat), lists, concurrency, surgeRuleExt)
}
