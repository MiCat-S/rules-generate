package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yuu518/rules-generate/internal/model"
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
