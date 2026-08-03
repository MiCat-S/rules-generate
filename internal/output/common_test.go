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
	lines.add(model.DomainRegexp, "z*.example.com", "DOMAIN-WILDCARD,z*.example.com")
	lines.add(model.DomainFull, "b.example.com", "DOMAIN,b.example.com")
	lines.add(model.DomainKeyword, "ads", "DOMAIN-KEYWORD,ads")
	lines.add(model.DomainFull, "a.example.com", "DOMAIN,a.example.com")
	lines.add(model.DomainSuffix, "example.net", "DOMAIN-SUFFIX,example.net")
	lines.add(model.DomainFull, "b.example.com", "DOMAIN,b.example.com")

	got := lines.sorted()
	want := []string{
		"DOMAIN,a.example.com",
		"DOMAIN,b.example.com",
		"DOMAIN-SUFFIX,example.net",
		"DOMAIN-KEYWORD,ads",
		"DOMAIN-WILDCARD,z*.example.com",
	}

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sorted() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const mtalkRegex = `^(alt[1-8]-)?mtalk4?(-(staging|dev))?\.google\.com$`

func writeSurge(t *testing.T, rules []model.DomainRule) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.list")
	if _, err := saveSurgeRuleSet(rules, path, true); err != nil {
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
		{Type: model.DomainRegexp, Value: mtalkRegex},
		{Type: model.DomainSuffix, Value: "example.net"},
		{Type: model.DomainKeyword, Value: "ads"},
		{Type: model.DomainFull, Value: "a.example.org"},
	})

	want := strings.Join([]string{
		"DOMAIN,a.example.org",
		"DOMAIN,mtalk-dev.google.com",
		"DOMAIN,mtalk-staging.google.com",
		"DOMAIN,mtalk.google.com",
		"DOMAIN,mtalk4-dev.google.com",
		"DOMAIN,mtalk4-staging.google.com",
		"DOMAIN,mtalk4.google.com",
		"DOMAIN-SUFFIX,example.net",
		"DOMAIN-KEYWORD,ads",
		"DOMAIN-WILDCARD,alt?-mtalk-dev.google.com",
		"DOMAIN-WILDCARD,alt?-mtalk-staging.google.com",
		"DOMAIN-WILDCARD,alt?-mtalk.google.com",
		"DOMAIN-WILDCARD,alt?-mtalk4-dev.google.com",
		"DOMAIN-WILDCARD,alt?-mtalk4-staging.google.com",
		"DOMAIN-WILDCARD,alt?-mtalk4.google.com",
		"",
	}, "\n")

	if got != want {
		t.Errorf("saveSurgeRuleSet() =\n%s\nwant\n%s", got, want)
	}
}

func TestSaveSurgeRuleSetDropsCoveredExpansions(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainSuffix, Value: "google.com"},
		{Type: model.DomainRegexp, Value: mtalkRegex},
	})

	if got != "DOMAIN-SUFFIX,google.com\n" {
		t.Errorf("saveSurgeRuleSet() = %q, want only the covering suffix", got)
	}
}

func TestSaveSurgeRuleSetDropsRulesCoveredByConvertedSuffix(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainFull, Value: "a.okaapps.com"},
		{Type: model.DomainRegexp, Value: `(^|\.)okaapps\.com$`},
	})

	if got != "DOMAIN-SUFFIX,okaapps.com\n" {
		t.Errorf("saveSurgeRuleSet() = %q, want only the converted suffix", got)
	}
}

func TestSaveSurgeRuleSetKeepsRulesUnderTopLevelDomain(t *testing.T) {
	got := writeSurge(t, []model.DomainRule{
		{Type: model.DomainSuffix, Value: "com"},
		{Type: model.DomainFull, Value: "a.example.com"},
		{Type: model.DomainRegexp, Value: `^ewcdn[0-9]+\.nowe\.com$`},
	})

	want := strings.Join([]string{
		"DOMAIN,a.example.com",
		"DOMAIN-SUFFIX,com",
		"DOMAIN-WILDCARD,ewcdn*.nowe.com",
		"",
	}, "\n")

	if got != want {
		t.Errorf("saveSurgeRuleSet() =\n%s\nwant\n%s", got, want)
	}
}

func TestWildcardTail(t *testing.T) {
	cases := map[string]string{
		"alt?-mtalk.google.com": "google.com",
		"*.foo.com":             "foo.com",
		"*javdb*.com":           "com",
		"plain.example.com":     "plain.example.com",
		"*":                     "",
	}

	for pattern, want := range cases {
		if got := wildcardTail(pattern); got != want {
			t.Errorf("wildcardTail(%q) = %q, want %q", pattern, got, want)
		}
	}
}
