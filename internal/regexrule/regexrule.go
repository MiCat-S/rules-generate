package regexrule

import (
	"sort"
	"strconv"
	"strings"
)

const (
	maxVariants     = 32
	minLiteralChars = 4
)

type anchorKind int

const (
	anchorExact anchorKind = iota
	anchorSuffix
	anchorSubdomain
	anchorTail
)

const (
	suffixPrefix    = `(^|\.)`
	subdomainPrefix = `.+\.`
	subdomainStar   = `.*\.`
)

type Kind int

const (
	KindFull Kind = iota
	KindSuffix
	KindWildcard
)

type Rule struct {
	Kind  Kind
	Value string
}

func ToRules(pattern string) ([]Rule, bool) {
	if !strings.HasSuffix(pattern, "$") {
		return nil, false
	}
	body := strings.TrimSuffix(pattern, "$")

	anchor := anchorTail
	switch {
	case strings.HasPrefix(body, suffixPrefix):
		anchor = anchorSuffix
		body = body[len(suffixPrefix):]
	case strings.HasPrefix(body, subdomainPrefix), strings.HasPrefix(body, subdomainStar):
		anchor = anchorSubdomain
		body = body[len(subdomainPrefix):]
	case strings.HasPrefix(body, "^"):
		anchor = anchorExact
		body = body[1:]
	}

	p := &parser{src: body}
	variants, ok := p.alternation()
	if !ok || p.pos != len(p.src) {
		return nil, false
	}

	seen := make(map[Rule]bool)
	var out []Rule
	for _, variant := range variants {
		body := normalize(variant)
		if !acceptable(body) {
			continue
		}
		for _, candidate := range applyAnchor(anchor, body) {
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, true
}

func applyAnchor(anchor anchorKind, value string) []Rule {
	literal := !strings.ContainsAny(value, "*?")
	switch anchor {
	case anchorSuffix:
		if literal {
			return []Rule{{KindSuffix, value}}
		}
		return []Rule{{KindWildcard, value}, {KindWildcard, "*." + value}}
	case anchorSubdomain:
		return []Rule{{KindWildcard, "*." + value}}
	case anchorTail:
		return []Rule{{KindWildcard, "*" + value}}
	default:
		if literal {
			return []Rule{{KindFull, value}}
		}
		return []Rule{{KindWildcard, value}}
	}
}

func normalize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if !isWildcard(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j, star := i, false
		for j < len(s) && isWildcard(s[j]) {
			if s[j] == '*' {
				star = true
			}
			j++
		}
		if star {
			b.WriteByte('*')
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

func isWildcard(c byte) bool {
	return c == '*' || c == '?'
}

func acceptable(s string) bool {
	literals, dots := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case isWildcard(s[i]):
		case s[i] == '.':
			dots++
		default:
			literals++
		}
	}
	return literals >= minLiteralChars && dots >= 1
}

type parser struct {
	src string
	pos int
}

func (p *parser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

func (p *parser) alternation() ([]string, bool) {
	variants, ok := p.sequence()
	if !ok {
		return nil, false
	}
	for p.peek() == '|' {
		p.pos++
		next, ok := p.sequence()
		if !ok {
			return nil, false
		}
		variants = append(variants, next...)
	}
	if len(variants) > maxVariants {
		return []string{"*"}, true
	}
	return variants, true
}

func (p *parser) sequence() ([]string, bool) {
	variants := []string{""}
	for {
		switch p.peek() {
		case 0, '|', ')':
			return variants, true
		}
		atom, ok := p.atom()
		if !ok {
			return nil, false
		}
		atom = p.quantify(atom)
		if len(variants)*len(atom) > maxVariants {
			atom = []string{"*"}
		}
		variants = cross(variants, atom)
	}
}

func (p *parser) atom() ([]string, bool) {
	switch c := p.peek(); c {
	case '(':
		p.pos++
		if strings.HasPrefix(p.src[p.pos:], "?:") {
			p.pos += 2
		}
		inner, ok := p.alternation()
		if !ok || p.peek() != ')' {
			return nil, false
		}
		p.pos++
		return inner, true
	case '[':
		if !p.skipClass() {
			return nil, false
		}
		return []string{"?"}, true
	case '\\':
		p.pos++
		if p.pos >= len(p.src) {
			return nil, false
		}
		escaped := p.src[p.pos]
		p.pos++
		if strings.IndexByte("dwsDWS", escaped) >= 0 {
			return []string{"?"}, true
		}
		if isWildcard(escaped) {
			return nil, false
		}
		return []string{string(escaped)}, true
	case '.':
		p.pos++
		return []string{"?"}, true
	case '^', '$':
		p.pos++
		return []string{""}, true
	case '*', '?', '+', '{':
		return nil, false
	default:
		p.pos++
		return []string{string(c)}, true
	}
}

func (p *parser) skipClass() bool {
	p.pos++
	if p.peek() == '^' {
		p.pos++
	}
	if p.peek() == ']' {
		p.pos++
	}
	for p.pos < len(p.src) && p.src[p.pos] != ']' {
		if p.src[p.pos] == '\\' {
			p.pos++
		}
		p.pos++
	}
	if p.pos >= len(p.src) {
		return false
	}
	p.pos++
	return true
}

func (p *parser) quantify(atom []string) []string {
	var result []string
	switch p.peek() {
	case '?':
		p.pos++
		if isStar(atom) {
			result = atom
		} else {
			result = append(append([]string{}, atom...), "")
		}
	case '*', '+':
		p.pos++
		result = []string{"*"}
	case '{':
		result = p.repeat(atom)
	default:
		return atom
	}
	if p.peek() == '?' {
		p.pos++
	}
	return result
}

func (p *parser) repeat(atom []string) []string {
	end := strings.IndexByte(p.src[p.pos:], '}')
	if end < 0 {
		p.pos = len(p.src)
		return []string{"*"}
	}
	spec := p.src[p.pos+1 : p.pos+end]
	p.pos += end + 1

	min, max, ok := parseRepeatSpec(spec)
	if !ok || max-min > 3 {
		return []string{"*"}
	}

	var result []string
	for count := min; count <= max; count++ {
		folded := fold(atom, count)
		if isStar(folded) {
			return []string{"*"}
		}
		result = append(result, folded...)
		if len(result) > maxVariants {
			return []string{"*"}
		}
	}
	return result
}

func parseRepeatSpec(spec string) (int, int, bool) {
	lower, upper, hasComma := strings.Cut(spec, ",")
	min, err := strconv.Atoi(strings.TrimSpace(lower))
	if err != nil || min < 0 {
		return 0, 0, false
	}
	if !hasComma {
		return min, min, true
	}
	if strings.TrimSpace(upper) == "" {
		return 0, 0, false
	}
	max, err := strconv.Atoi(strings.TrimSpace(upper))
	if err != nil || max < min {
		return 0, 0, false
	}
	return min, max, true
}

func fold(atom []string, count int) []string {
	result := []string{""}
	for i := 0; i < count; i++ {
		if len(result)*len(atom) > maxVariants {
			return []string{"*"}
		}
		result = cross(result, atom)
	}
	return result
}

func cross(a, b []string) []string {
	result := make([]string, 0, len(a)*len(b))
	for _, left := range a {
		for _, right := range b {
			result = append(result, left+right)
		}
	}
	return result
}

func isStar(variants []string) bool {
	return len(variants) == 1 && variants[0] == "*"
}
