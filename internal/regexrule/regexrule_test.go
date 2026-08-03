package regexrule

import (
	"regexp"
	"strings"
	"testing"
)

func TestToRules(t *testing.T) {
	cases := []struct {
		pattern string
		want    []Rule
	}{
		{
			pattern: `(^|\.)zzz[1-9][0-9]\.top$`,
			want: []Rule{
				{KindWildcard, "*.zzz??.top"},
				{KindWildcard, "zzz??.top"},
			},
		},
		{
			pattern: `^epicgames-download\d\.akamaized\.net$`,
			want:    []Rule{{KindWildcard, "epicgames-download?.akamaized.net"}},
		},
		{
			pattern: `(^|\.)fi11sm([0-9]+)?\.com$`,
			want: []Rule{
				{KindWildcard, "*.fi11sm*.com"},
				{KindWildcard, "fi11sm*.com"},
			},
		},
		{
			pattern: `.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`,
			want: []Rule{
				{KindWildcard, "*.awsdns-??.co.uk"},
				{KindWildcard, "*.awsdns-??.com"},
				{KindWildcard, "*.awsdns-??.net"},
				{KindWildcard, "*.awsdns-??.org"},
			},
		},
		{
			pattern: `javdb\d+\.com$`,
			want:    []Rule{{KindWildcard, "*javdb*.com"}},
		},
		{
			pattern: `^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`,
			want:    []Rule{{KindWildcard, "chatgpt-async-webps-prod-*-*.webpubsub.azure.com"}},
		},
		{
			pattern: `^(.+\.)*zh\.okaapps\.com$`,
			want:    []Rule{{KindWildcard, "*zh.okaapps.com"}},
		},
		{
			pattern: `(^|\.)youyuapi\..+$`,
			want: []Rule{
				{KindWildcard, "*.youyuapi.*"},
				{KindWildcard, "youyuapi.*"},
			},
		},
		{
			pattern: `.+\.dkr\.ecr\.[^\.]+\.amazonaws\.com$`,
			want:    []Rule{{KindWildcard, "*.dkr.ecr.*.amazonaws.com"}},
		},
		{
			pattern: `^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$`,
			want: []Rule{
				{KindWildcard, "speed.coe.ad.*.prod.hosts.ooklaserver.net"},
				{KindWildcard, "speed.open.ad.*.prod.hosts.ooklaserver.net"},
			},
		},
		{
			pattern: `(^|\.)doufuru[0-9]{2}?\.xyz$`,
			want: []Rule{
				{KindWildcard, "*.doufuru??.xyz"},
				{KindWildcard, "doufuru??.xyz"},
			},
		},
		{
			pattern: `(^|\.)luchuxue([0-9]{0,5})\.buzz$`,
			want: []Rule{
				{KindWildcard, "*.luchuxue*.buzz"},
				{KindWildcard, "luchuxue*.buzz"},
			},
		},
		{
			pattern: `^mtalk\.google\.com$`,
			want:    []Rule{{KindFull, "mtalk.google.com"}},
		},
		{
			pattern: `(^|\.)okaapps\.com$`,
			want:    []Rule{{KindSuffix, "okaapps.com"}},
		},
		{
			pattern: `^(alt[1-8]-)?mtalk4?(-(staging|dev))?\.google\.com$`,
			want: []Rule{
				{KindFull, "mtalk-dev.google.com"},
				{KindFull, "mtalk-staging.google.com"},
				{KindFull, "mtalk.google.com"},
				{KindFull, "mtalk4-dev.google.com"},
				{KindFull, "mtalk4-staging.google.com"},
				{KindFull, "mtalk4.google.com"},
				{KindWildcard, "alt?-mtalk-dev.google.com"},
				{KindWildcard, "alt?-mtalk-staging.google.com"},
				{KindWildcard, "alt?-mtalk.google.com"},
				{KindWildcard, "alt?-mtalk4-dev.google.com"},
				{KindWildcard, "alt?-mtalk4-staging.google.com"},
				{KindWildcard, "alt?-mtalk4.google.com"},
			},
		},
		{
			pattern: `(^|\.)speed\.(coe|open)\.ooklaserver\.net$`,
			want: []Rule{
				{KindSuffix, "speed.coe.ooklaserver.net"},
				{KindSuffix, "speed.open.ooklaserver.net"},
			},
		},
	}

	for _, tc := range cases {
		got, ok := ToRules(tc.pattern)
		if !ok {
			t.Errorf("ToRules(%q) = not ok, want %v", tc.pattern, tc.want)
			continue
		}
		if !equal(got, tc.want) {
			t.Errorf("ToRules(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

func TestToRulesRejects(t *testing.T) {
	cases := []string{
		`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`,
		`(^|\.)91cg([1-9]|[0-9][1-9])?.com$`,
		`^no-trailing-anchor\.com`,
	}

	for _, pattern := range cases {
		if got, ok := ToRules(pattern); ok {
			t.Errorf("ToRules(%q) = %v, want rejection", pattern, got)
		}
	}
}

func TestToRulesNeverMatchesEverything(t *testing.T) {
	cases := []string{
		`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`,
		`(^|\.)zzz[1-9][0-9]\.top$`,
		`javdb\d+\.com$`,
		`^(.+\.)*zh\.okaapps\.com$`,
	}

	for _, pattern := range cases {
		rules, ok := ToRules(pattern)
		if !ok {
			continue
		}
		for _, rule := range rules {
			if !acceptable(rule.Value) {
				t.Errorf("ToRules(%q) produced overly broad rule %v", pattern, rule)
			}
		}
	}
}

func TestToRulesCoversOriginalMatches(t *testing.T) {
	cases := []struct {
		pattern string
		domains []string
	}{
		{`(^|\.)zzz[1-9][0-9]\.top$`, []string{"zzz10.top", "zzz99.top", "www.zzz42.top"}},
		{`^epicgames-download\d\.akamaized\.net$`, []string{"epicgames-download0.akamaized.net", "epicgames-download7.akamaized.net"}},
		{`(^|\.)fi11sm([0-9]+)?\.com$`, []string{"fi11sm.com", "fi11sm123.com", "a.fi11sm9.com"}},
		{`.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`, []string{"ns.awsdns-01.co.uk", "ns.awsdns-99.org"}},
		{`javdb\d+\.com$`, []string{"javdb1.com", "javdb456.com"}},
		{`^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`, []string{"chatgpt-async-webps-prod-abc-12.webpubsub.azure.com"}},
		{`(^|\.)youyuapi\..+$`, []string{"youyuapi.com", "cdn.youyuapi.net"}},
		{`.+\.dkr\.ecr\.[^\.]+\.amazonaws\.com$`, []string{"123.dkr.ecr.us-east-1.amazonaws.com"}},
		{`^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$`, []string{"speed.coe.ad.abcd.prod.hosts.ooklaserver.net"}},
		{`(^|\.)luchuxue([0-9]{0,5})\.buzz$`, []string{"luchuxue.buzz", "luchuxue12345.buzz"}},
		{`^(alt[1-8]-)?mtalk4?(-(staging|dev))?\.google\.com$`, []string{"mtalk.google.com", "mtalk4.google.com", "mtalk4-dev.google.com", "alt3-mtalk-staging.google.com"}},
		{`(^|\.)okaapps\.com$`, []string{"okaapps.com", "zh.okaapps.com", "a.b.okaapps.com"}},
	}

	for _, tc := range cases {
		re, err := regexp.Compile(tc.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.pattern, err)
		}
		rules, ok := ToRules(tc.pattern)
		if !ok {
			t.Errorf("ToRules(%q) = not ok", tc.pattern)
			continue
		}
		for _, domain := range tc.domains {
			if !re.MatchString(domain) {
				t.Fatalf("test data error: %q does not match %q", domain, tc.pattern)
			}
			if !matchesAny(rules, domain) {
				t.Errorf("ToRules(%q) = %v, does not cover %q", tc.pattern, rules, domain)
			}
		}
	}
}

func TestToRulesKeepsExactAnchorExact(t *testing.T) {
	cases := []struct {
		pattern string
		domains []string
	}{
		{`^(alt[1-8]-)?mtalk4?(-(staging|dev))?\.google\.com$`, []string{"x.mtalk.google.com", "a.mtalk4-dev.google.com"}},
		{`^mtalk\.google\.com$`, []string{"x.mtalk.google.com", "mtalk.google.com.cn"}},
	}

	for _, tc := range cases {
		re, err := regexp.Compile(tc.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.pattern, err)
		}
		rules, ok := ToRules(tc.pattern)
		if !ok {
			t.Errorf("ToRules(%q) = not ok", tc.pattern)
			continue
		}
		for _, domain := range tc.domains {
			if re.MatchString(domain) {
				t.Fatalf("test data error: %q matches %q", domain, tc.pattern)
			}
			if matchesAny(rules, domain) {
				t.Errorf("ToRules(%q) = %v, wrongly covers %q", tc.pattern, rules, domain)
			}
		}
	}
}

func matchesAny(rules []Rule, s string) bool {
	for _, rule := range rules {
		if ruleMatch(rule, s) {
			return true
		}
	}
	return false
}

func ruleMatch(rule Rule, s string) bool {
	switch rule.Kind {
	case KindFull:
		return s == rule.Value
	case KindSuffix:
		return s == rule.Value || strings.HasSuffix(s, "."+rule.Value)
	default:
		return wildcardMatch(rule.Value, s)
	}
}

func wildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	starP, starI := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
			p++
		case starP >= 0:
			starI++
			p, i = starP+1, starI
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func equal(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
