package resolver

import (
	"testing"

	"github.com/Yuu518/rules-generate/internal/model"
)

func newList(name model.FileName) *model.ListInfo {
	l := model.NewListInfo()
	l.Name = name
	return l
}

func resolveToRules(t *testing.T, l *model.ListInfo, code string) []model.DomainRule {
	t.Helper()
	lm := model.ListInfoMap{l.Name: l}
	if err := Resolve(lm); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return ToRuleMap(lm, nil)[code]
}

func TestToRuleMapKeepsTopLevelDomainsWithoutCovering(t *testing.T) {
	l := newList("CN")
	l.SuffixList = []model.DomainRule{
		{Type: model.DomainSuffix, Value: "cn"},
		{Type: model.DomainSuffix, Value: "a.cn"},
		{Type: model.DomainSuffix, Value: "s.cn"},
		{Type: model.DomainSuffix, Value: "deep.a.cn"},
	}
	l.FullList = []model.DomainRule{
		{Type: model.DomainFull, Value: "b.a.cn"},
		{Type: model.DomainFull, Value: "under.cn"},
		{Type: model.DomainFull, Value: "keep.example.com"},
	}

	got := resolveToRules(t, l, "cn")
	want := []model.DomainRule{
		{Type: model.DomainFull, Value: "under.cn"},
		{Type: model.DomainFull, Value: "keep.example.com"},
		{Type: model.DomainSuffix, Value: "cn"},
		{Type: model.DomainSuffix, Value: "a.cn"},
		{Type: model.DomainSuffix, Value: "s.cn"},
	}

	assertRules(t, got, want)
}

func TestToRuleMapKeepsAttributeRules(t *testing.T) {
	l := newList("X")
	l.SuffixList = []model.DomainRule{
		{Type: model.DomainSuffix, Value: "example.com"},
	}
	l.AttributeRuleList = []model.DomainRule{
		{Type: model.DomainFull, Value: "a.example.com", Attributes: []string{"ads"}},
		{Type: model.DomainSuffix, Value: "b.example.com", Attributes: []string{"ads"}},
	}

	got := resolveToRules(t, l, "x")
	want := []model.DomainRule{
		{Type: model.DomainSuffix, Value: "example.com"},
		{Type: model.DomainFull, Value: "a.example.com", Attributes: []string{"ads"}},
		{Type: model.DomainSuffix, Value: "b.example.com", Attributes: []string{"ads"}},
	}

	assertRules(t, got, want)
}

func TestToRuleMapKeepsKeywordAndDropsDuplicates(t *testing.T) {
	l := newList("Y")
	l.SuffixList = []model.DomainRule{
		{Type: model.DomainSuffix, Value: "example.com"},
	}
	l.FullList = []model.DomainRule{
		{Type: model.DomainFull, Value: "dup.net"},
		{Type: model.DomainFull, Value: "dup.net"},
	}
	l.KeywordList = []model.DomainRule{
		{Type: model.DomainKeyword, Value: "example"},
	}

	got := resolveToRules(t, l, "y")
	want := []model.DomainRule{
		{Type: model.DomainFull, Value: "dup.net"},
		{Type: model.DomainSuffix, Value: "example.com"},
		{Type: model.DomainKeyword, Value: "example"},
	}

	assertRules(t, got, want)
}

func assertRules(t *testing.T, got, want []model.DomainRule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i].Type != want[i].Type || got[i].Value != want[i].Value {
			t.Fatalf("got %v, want %v", got, want)
		}
		if len(got[i].Attributes) != len(want[i].Attributes) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
