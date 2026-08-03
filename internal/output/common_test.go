package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yuu518/rules-generate/internal/model"
)

func TestRuleLinesSorted(t *testing.T) {
	var lines ruleLines
	lines.add(model.DomainKeyword, "ads", "DOMAIN-KEYWORD,ads")
	lines.add(model.DomainFull, "b.example.com", "DOMAIN,b.example.com")
	lines.add(model.DomainFull, "a.example.com", "DOMAIN,a.example.com")
	lines.add(model.DomainSuffix, "example.net", "DOMAIN-SUFFIX,example.net")
	lines.add(model.DomainFull, "b.example.com", "DOMAIN,b.example.com")

	got := lines.sorted()
	want := []string{
		"DOMAIN,a.example.com",
		"DOMAIN,b.example.com",
		"DOMAIN-SUFFIX,example.net",
		"DOMAIN-KEYWORD,ads",
	}

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sorted() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func writeSurge(t *testing.T, rules []model.DomainRule) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.list")
	if err := saveSurgeRuleSet(rules, path); err != nil {
		t.Fatalf("saveSurgeRuleSet: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func TestSaveSurgeRuleSetGroupsByType(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainSuffix, Value: "example.net"},
		{Type: model.DomainKeyword, Value: "ads"},
		{Type: model.DomainFull, Value: "a.example.org"},
		{Type: model.DomainFull, Value: "b.example.org"},
	})

	want := strings.Join([]string{
		"DOMAIN,a.example.org",
		"DOMAIN,b.example.org",
		"DOMAIN-SUFFIX,example.net",
		"DOMAIN-KEYWORD,ads",
		"",
	}, "\n")

	if got != want {
		t.Errorf("saveSurgeRuleSet() =\n%s\nwant\n%s", got, want)
	}
}

func TestSaveSurgeRuleSetDropsRulesCoveredBySuffix(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainFull, Value: "a.okaapps.com"},
		{Type: model.DomainSuffix, Value: "okaapps.com"},
		{Type: model.DomainSuffix, Value: "deep.okaapps.com"},
	})

	if got != "DOMAIN-SUFFIX,okaapps.com\n" {
		t.Errorf("saveSurgeRuleSet() = %q, want only the covering suffix", got)
	}
}

func TestSaveSurgeRuleSetKeepsRulesUnderTopLevelDomain(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainSuffix, Value: "com"},
		{Type: model.DomainFull, Value: "a.example.com"},
	})

	want := strings.Join([]string{
		"DOMAIN,a.example.com",
		"DOMAIN-SUFFIX,com",
		"",
	}, "\n")

	if got != want {
		t.Errorf("saveSurgeRuleSet() =\n%s\nwant\n%s", got, want)
	}
}
