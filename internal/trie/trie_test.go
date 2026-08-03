package trie

import "testing"

func TestCovers(t *testing.T) {
	tr := NewDomainTrie()
	for _, domain := range []string{"google.com", "a.cn"} {
		if _, err := tr.Insert(domain); err != nil {
			t.Fatalf("Insert(%q): %v", domain, err)
		}
	}

	cases := []struct {
		domain string
		want   bool
	}{
		{"google.com", true},
		{"mtalk.google.com", true},
		{"a.b.google.com", true},
		{"notgoogle.com", false},
		{"com", false},
		{"google.com.cn", false},
		{"a.cn", true},
		{"b.a.cn", true},
		{"s.cn", false},
		{"cn", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := tr.Covers(tc.domain); got != tc.want {
			t.Errorf("Covers(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestInsertRequiresAscendingLabelCount(t *testing.T) {
	ascending := NewDomainTrie()
	if success, _ := ascending.Insert("com"); !success {
		t.Fatal(`Insert("com") = false, want true`)
	}
	if success, _ := ascending.Insert("a.com"); success {
		t.Error(`Insert("a.com") = true, want false (covered by "com")`)
	}
	if !ascending.Covers("x.com") {
		t.Error(`Covers("x.com") = false, want true`)
	}

	descending := NewDomainTrie()
	if success, _ := descending.Insert("a.com"); !success {
		t.Fatal(`Insert("a.com") = false, want true`)
	}
	if success, _ := descending.Insert("com"); success {
		t.Error(`Insert("com") = true; inserting out of order is expected to fail`)
	}
	if descending.Covers("x.com") {
		t.Error(`Covers("x.com") = true; "com" was never stored, callers must sort by label count`)
	}
}
