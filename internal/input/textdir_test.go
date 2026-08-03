package input

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yuu518/rules-generate/internal/model"
)

func TestParseFileDropsRegexpRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test")
	content := strings.Join([]string{
		`regexp:^a\.example\.com$`,
		`regexp:^b\.example\.com$ @ads`,
		"full:a.example.com",
		"domain:example.com",
		"keyword:example",
		"domain:b.example.com @ads",
		"bare.example.org",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	list, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	for _, rule := range allRules(list) {
		if strings.Contains(rule.Value, `\.`) {
			t.Errorf("regexp rule leaked into output: %+v", rule)
		}
	}

	assertValues(t, "FullList", list.FullList, []string{"a.example.com"})
	assertValues(t, "SuffixList", list.SuffixList, []string{"example.com", "bare.example.org"})
	assertValues(t, "KeywordList", list.KeywordList, []string{"example"})
	assertValues(t, "AttributeRuleList", list.AttributeRuleList, []string{"b.example.com"})

	if len(list.AttributeRuleMap) != 1 {
		t.Errorf("AttributeRuleMap = %v, want a single @ads entry", list.AttributeRuleMap)
	}
	assertValues(t, "AttributeRuleMap[@ads]", list.AttributeRuleMap["@ads"], []string{"b.example.com"})
}

func allRules(list *model.ListInfo) []model.DomainRule {
	rules := append([]model.DomainRule{}, list.FullList...)
	rules = append(rules, list.SuffixList...)
	rules = append(rules, list.KeywordList...)
	rules = append(rules, list.AttributeRuleList...)
	for _, attrRules := range list.AttributeRuleMap {
		rules = append(rules, attrRules...)
	}
	return rules
}

func assertValues(t *testing.T, name string, rules []model.DomainRule, want []string) {
	t.Helper()
	got := make([]string, 0, len(rules))
	for _, rule := range rules {
		got = append(got, rule.Value)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}
