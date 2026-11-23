package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yuu518/rules-generate/internal/model"
	mihomo "github.com/metacubex/mihomo/constant"
	mihomoRules "github.com/metacubex/mihomo/rules"
	mihomoProvider "github.com/metacubex/mihomo/rules/provider"
	"gopkg.in/yaml.v3"
)

func TestExportConvertedWritesSixFlatClientDirectories(t *testing.T) {
	root := t.TempDir()
	jsonPath := filepath.Join(root, "source.json")
	srsPath := filepath.Join(root, "source.srs")
	if err := os.WriteFile(jsonPath, []byte(`{"version":2,"rules":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srsPath, []byte("srs"), 0644); err != nil {
		t.Fatal(err)
	}
	rules := model.SourceRuleSetMap{
		"site-sample": {
			Domains: []model.DomainRule{
				{Type: model.DomainFull, Value: "exact.example"},
				{Type: model.DomainSuffix, Value: "suffix.example"},
			},
			IPCIDR:         []string{"192.0.2.0/24", "2001:db8::/32"},
			SourceJSONPath: jsonPath,
			SourceSRSPath:  srsPath,
		},
	}

	report, err := ExportConverted(rules, root, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if report.ConvertedRuleSets != 1 || report.Rules != 4 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, target := range clientDirectories {
		entries, err := os.ReadDir(filepath.Join(root, target))
		if err != nil || len(entries) == 0 {
			t.Fatalf("%s output missing", target)
		}
	}
	qx, err := os.ReadFile(filepath.Join(root, "quantumult-x", "site-sample.list"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(qx), "ip6-cidr,2001:db8::/32,proxy") {
		t.Fatalf("unexpected Quantumult X output: %s", qx)
	}
}

func TestExportConvertedReportsBinaryOnlyRuleSets(t *testing.T) {
	root := t.TempDir()
	srsPath := filepath.Join(root, "only.srs")
	if err := os.WriteFile(srsPath, []byte("srs"), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := ExportConverted(model.SourceRuleSetMap{
		"site-binary": {SourceSRSPath: srsPath},
	}, root, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.BinaryOnly) != 1 || report.BinaryOnly[0] != "site-binary" {
		t.Fatalf("binary-only report = %v", report.BinaryOnly)
	}
}

func TestExportConvertedDomainRegex(t *testing.T) {
	root := t.TempDir()
	pattern := `^api[0-9]{1,3}\.example$`
	source := `{"version":2,"rules":[{"domain_regex":["^api[0-9]{1,3}\\.example$"]}]}`
	sourcePath := filepath.Join(root, "source.json")
	if err := os.WriteFile(sourcePath, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := ExportConverted(model.SourceRuleSetMap{
		"site-mixed": {
			Domains:        []model.DomainRule{{Type: model.DomainFull, Value: "static.example"}},
			DomainRegex:    []string{pattern},
			SourceJSONPath: sourcePath,
		},
		"site-regex-only": {DomainRegex: []string{pattern}, SourceJSONPath: sourcePath},
	}, root, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if skips := report.SkippedDomainRegex.RuleSets; report.Rules != 3 || len(skips) != 2 || skips["site-mixed"] != 1 || skips["site-regex-only"] != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, target := range []string{"surge", "loon", "shadowrocket", "quantumult-x"} {
		want := "DOMAIN,static.example\n"
		if target == "quantumult-x" {
			want = "host,static.example,proxy\n"
		}
		content, err := os.ReadFile(filepath.Join(root, target, "site-mixed.list"))
		if err != nil || string(content) != want {
			t.Fatalf("%s mixed output = %q, %v", target, content, err)
		}
		if _, err := os.Stat(filepath.Join(root, target, "site-regex-only.list")); !os.IsNotExist(err) {
			t.Fatalf("%s regex-only output should be absent: %v", target, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(root, "sing-box", "site-regex-only.json"))
	if err != nil || string(content) != source {
		t.Fatalf("sing-box source copy = %q, %v", content, err)
	}
	content, err = os.ReadFile(filepath.Join(root, "mihomo", "site-regex-only.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var provider struct{ Payload []string }
	if err := yaml.Unmarshal(content, &provider); err != nil {
		t.Fatal(err)
	}
	strategy := mihomoProvider.NewClassicalStrategy(mihomoRules.ParseRule)
	for _, line := range provider.Payload {
		strategy.Insert(line)
	}
	if strategy.Count() != 1 || !strategy.Match(&mihomo.Metadata{Host: "api123.example"}, mihomo.RuleMatchHelper{}) ||
		strategy.Match(&mihomo.Metadata{Host: "api1234.example"}, mihomo.RuleMatchHelper{}) {
		t.Fatalf("Mihomo provider did not preserve the regex quantifier: %v", provider.Payload)
	}
}
