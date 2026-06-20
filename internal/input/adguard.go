package input

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yuu518/rules-generate/internal/model"
	"github.com/sagernet/sing-box/common/convertor/adguard"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// ParseAdGuardFile parses a single AdGuard filter file into sing-box headless
// rules by reusing sing-box's built-in converter.
func ParseAdGuardFile(path string) ([]option.HeadlessRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return adguard.ToOptions(file, logger.NOP())
}

// ParseAdGuard parses an AdGuard filter file or a directory of filter files.
// Each file becomes one rule set keyed by its base name (without extension,
// lowercased). Files that contain no convertible rules are skipped with a
// warning rather than failing the whole run.
func ParseAdGuard(path string) (model.AdGuardRuleMap, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	ruleMap := make(model.AdGuardRuleMap)

	if !info.IsDir() {
		rules, err := ParseAdGuardFile(path)
		if err != nil {
			return nil, err
		}
		ruleMap[adguardListName(path)] = rules
		return ruleMap, nil
	}

	err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rules, err := ParseAdGuardFile(p)
		if err != nil {
			fmt.Printf("Skipping %s: %v\n", p, err)
			return nil
		}
		ruleMap[adguardListName(p)] = rules
		return nil
	})
	if err != nil {
		return nil, err
	}

	return ruleMap, nil
}

func adguardListName(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return strings.ToLower(base)
}
