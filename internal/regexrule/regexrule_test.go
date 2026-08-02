package regexrule

import (
	"regexp"
	"testing"
)

func TestToWildcard(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		{
			pattern: `(^|\.)zzz[1-9][0-9]\.top$`,
			want:    []string{"*.zzz??.top", "zzz??.top"},
		},
		{
			pattern: `^epicgames-download\d\.akamaized\.net$`,
			want:    []string{"epicgames-download?.akamaized.net"},
		},
		{
			pattern: `(^|\.)fi11sm([0-9]+)?\.com$`,
			want:    []string{"*.fi11sm*.com", "fi11sm*.com"},
		},
		{
			pattern: `.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`,
			want: []string{
				"*.awsdns-??.co.uk",
				"*.awsdns-??.com",
				"*.awsdns-??.net",
				"*.awsdns-??.org",
			},
		},
		{
			pattern: `javdb\d+\.com$`,
			want:    []string{"*javdb*.com"},
		},
		{
			pattern: `^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`,
			want:    []string{"chatgpt-async-webps-prod-*-*.webpubsub.azure.com"},
		},
		{
			pattern: `^(.+\.)*zh\.okaapps\.com$`,
			want:    []string{"*zh.okaapps.com"},
		},
		{
			pattern: `(^|\.)youyuapi\..+$`,
			want:    []string{"*.youyuapi.*", "youyuapi.*"},
		},
		{
			pattern: `.+\.dkr\.ecr\.[^\.]+\.amazonaws\.com$`,
			want:    []string{"*.dkr.ecr.*.amazonaws.com"},
		},
		{
			pattern: `^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$`,
			want: []string{
				"speed.coe.ad.*.prod.hosts.ooklaserver.net",
				"speed.open.ad.*.prod.hosts.ooklaserver.net",
			},
		},
		{
			pattern: `(^|\.)doufuru[0-9]{2}?\.xyz$`,
			want:    []string{"*.doufuru??.xyz", "doufuru??.xyz"},
		},
		{
			pattern: `(^|\.)luchuxue([0-9]{0,5})\.buzz$`,
			want:    []string{"*.luchuxue*.buzz", "luchuxue*.buzz"},
		},
	}

	for _, tc := range cases {
		got, ok := ToWildcard(tc.pattern)
		if !ok {
			t.Errorf("ToWildcard(%q) = not ok, want %v", tc.pattern, tc.want)
			continue
		}
		if !equal(got, tc.want) {
			t.Errorf("ToWildcard(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

func TestToWildcardRejects(t *testing.T) {
	cases := []string{
		`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`,
		`(^|\.)91cg([1-9]|[0-9][1-9])?.com$`,
		`^no-trailing-anchor\.com`,
	}

	for _, pattern := range cases {
		if got, ok := ToWildcard(pattern); ok {
			t.Errorf("ToWildcard(%q) = %v, want rejection", pattern, got)
		}
	}
}

func TestToWildcardNeverMatchesEverything(t *testing.T) {
	cases := []string{
		`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`,
		`(^|\.)zzz[1-9][0-9]\.top$`,
		`javdb\d+\.com$`,
		`^(.+\.)*zh\.okaapps\.com$`,
	}

	for _, pattern := range cases {
		patterns, ok := ToWildcard(pattern)
		if !ok {
			continue
		}
		for _, p := range patterns {
			if !acceptable(p) {
				t.Errorf("ToWildcard(%q) produced overly broad pattern %q", pattern, p)
			}
		}
	}
}

func TestToWildcardCoversOriginalMatches(t *testing.T) {
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
	}

	for _, tc := range cases {
		re, err := regexp.Compile(tc.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.pattern, err)
		}
		patterns, ok := ToWildcard(tc.pattern)
		if !ok {
			t.Errorf("ToWildcard(%q) = not ok", tc.pattern)
			continue
		}
		for _, domain := range tc.domains {
			if !re.MatchString(domain) {
				t.Fatalf("test data error: %q does not match %q", domain, tc.pattern)
			}
			if !matchesAny(patterns, domain) {
				t.Errorf("ToWildcard(%q) = %v, does not cover %q", tc.pattern, patterns, domain)
			}
		}
	}
}

func matchesAny(patterns []string, s string) bool {
	for _, pattern := range patterns {
		if wildcardMatch(pattern, s) {
			return true
		}
	}
	return false
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

func equal(a, b []string) bool {
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
