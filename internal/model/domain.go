package model

import "github.com/sagernet/sing-box/option"

type DomainType int

const (
	DomainFull DomainType = iota
	DomainSuffix
	DomainKeyword
)

type DomainRule struct {
	Type       DomainType
	Value      string
	Attributes []string
}

type FileName string
type AttrKey string

type ListInfo struct {
	Name                  FileName
	HasInclusion          bool
	InclusionAttributeMap map[FileName][]AttrKey
	FullList              []DomainRule
	SuffixList            []DomainRule
	SuffixUniqueList      []DomainRule
	KeywordList           []DomainRule
	AttributeRuleMap      map[AttrKey][]DomainRule
	AttributeRuleList     []DomainRule
}

type ListInfoMap map[FileName]*ListInfo

type RuleMap map[string][]DomainRule

type IPRuleMap map[string][]string

// SourceRuleSet is a policy-free sing-box source rule-set prepared for
// conversion to client-specific external rule-set formats.
type SourceRuleSet struct {
	Domains        []DomainRule
	DomainRegex    []string
	IPCIDR         []string
	SourceJSONPath string
	SourceSRSPath  string
}

type SourceRuleSetMap map[string]*SourceRuleSet

// AdGuardRuleMap maps a rule-set name to the sing-box headless rules produced
// from an AdGuard filter. These rules use the AdGuardDomain matcher, which only
// sing-box's .srs format can represent.
type AdGuardRuleMap map[string][]option.HeadlessRule

func NewListInfo() *ListInfo {
	return &ListInfo{
		InclusionAttributeMap: make(map[FileName][]AttrKey),
		FullList:              make([]DomainRule, 0, 10),
		SuffixList:            make([]DomainRule, 0, 10),
		SuffixUniqueList:      make([]DomainRule, 0, 10),
		KeywordList:           make([]DomainRule, 0, 10),
		AttributeRuleMap:      make(map[AttrKey][]DomainRule),
		AttributeRuleList:     make([]DomainRule, 0, 10),
	}
}
