package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSingBoxDirSupportsScalarAndArrayFields(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rule_set_site"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "rule_set_ip"), 0755); err != nil {
		t.Fatal(err)
	}
	site := `{"version":2,"rules":[{"domain":"exact.example","domain_suffix":[".example.com"],"domain_keyword":["ads"]}]}`
	ip := `{"version":2,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]}]}`
	if err := os.WriteFile(filepath.Join(root, "rule_set_site", "sample.json"), []byte(site), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rule_set_ip", "sample.json"), []byte(ip), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ParseSingBoxDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["site-sample"].Domains) != 3 {
		t.Fatalf("site domains = %d, want 3", len(got["site-sample"].Domains))
	}
	if len(got["ip-sample"].IPCIDR) != 2 {
		t.Fatalf("ip CIDRs = %d, want 2", len(got["ip-sample"].IPCIDR))
	}
}

func TestParseSingBoxDirRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"rule_set_site", "rule_set_ip"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	bad := `{"version":2,"rules":[{"process_name":["curl"]}]}`
	if err := os.WriteFile(filepath.Join(root, "rule_set_site", "bad.json"), []byte(bad), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSingBoxDir(root); err == nil {
		t.Fatal("expected unknown field error")
	}
}
