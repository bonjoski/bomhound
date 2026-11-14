package vex

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseKconfig(t *testing.T) {
	kconfigContent := `
# Automatically generated file; DO NOT EDIT.
# Linux/x86 6.6.0 Kernel Configuration
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_SMP=y
# CONFIG_BT is not set
# CONFIG_USB is not set
CONFIG_NETFILTER=m
CONFIG_LOCALVERSION="-microvm"
`

	cfg, err := ParseKconfig(strings.NewReader(kconfigContent))
	if err != nil {
		t.Fatalf("ParseKconfig failed: %v", err)
	}

	if !cfg.IsEnabled("CONFIG_64BIT") {
		t.Errorf("expected CONFIG_64BIT to be enabled")
	}
	if !cfg.IsEnabled("CONFIG_NETFILTER") {
		t.Errorf("expected CONFIG_NETFILTER to be enabled (module)")
	}
	if cfg.IsEnabled("CONFIG_BT") {
		t.Errorf("expected CONFIG_BT to NOT be enabled")
	}
	if cfg.IsEnabled("CONFIG_USB") {
		t.Errorf("expected CONFIG_USB to NOT be enabled")
	}
	if cfg.IsEnabled("CONFIG_NONEXISTENT") {
		t.Errorf("expected CONFIG_NONEXISTENT to NOT be enabled")
	}
	if cfg["CONFIG_LOCALVERSION"] != "-microvm" {
		t.Errorf("expected localversion -microvm, got %s", cfg["CONFIG_LOCALVERSION"])
	}
}

func TestParseKallsyms(t *testing.T) {
	kallsymsContent := `
0000000000000000 A fixed_percpu_data
ffffffff81000000 T startup_64
ffffffff81000100 t check_early_cpu_options
ffffffff81200000 T sys_call_table
ffffffffa0001000 t custom_mod_fn [custom_module]
`
	syms, err := ParseKallsyms(strings.NewReader(kallsymsContent))
	if err != nil {
		t.Fatalf("ParseKallsyms failed: %v", err)
	}

	expected := []string{"startup_64", "check_early_cpu_options", "sys_call_table", "custom_mod_fn"}
	for _, exp := range expected {
		if !syms[exp] {
			t.Errorf("expected symbol %s in parsed kallsyms", exp)
		}
	}

	if syms["nonexistent_func"] {
		t.Errorf("unexpected symbol in kallsyms")
	}
}

func TestOpenVEXDocumentSerialization(t *testing.T) {
	doc := NewOpenVEXDocument("test-author")
	doc.Statements = append(doc.Statements, Statement{
		Vulnerability: VulnerabilityIdent{
			Name: "CVE-2021-3564",
		},
		Products:        []string{"pkg:generic/microvm-kernel@6.6.0"},
		Status:          StatusNotAffected,
		Justification:   JustificationVulnerableCodeNotPresent,
		ImpactStatement: "Bluetooth disabled in kernel build.",
	})

	data, err := doc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed["@context"] != OpenVEXContext {
		t.Errorf("expected @context %s, got %v", OpenVEXContext, parsed["@context"])
	}
	if parsed["author"] != "test-author" {
		t.Errorf("expected author test-author, got %v", parsed["author"])
	}
	stmts, ok := parsed["statements"].([]interface{})
	if !ok || len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %v", parsed["statements"])
	}
}

func TestAnalyzeKernelReachability(t *testing.T) {
	cves := []KernelCVE{
		{
			ID:                "CVE-TEST-001",
			Title:             "Test Bluetooth vulnerability",
			Subsystem:         "Bluetooth",
			RequiredKconfig:   []string{"CONFIG_BT"},
			VulnerableSymbols: []string{"hci_sock_bind"},
		},
		{
			ID:                "CVE-TEST-002",
			Title:             "Test VFS vulnerability",
			Subsystem:         "VFS",
			RequiredKconfig:   []string{"CONFIG_FS_CONTEXT"},
			VulnerableSymbols: []string{"legacy_parse_param"},
		},
	}

	product := "pkg:generic/linux-microvm@6.6.0"

	// Scenario 1: Both disabled via Kconfig
	kconfigDisabled := KconfigMap{
		"CONFIG_BT":         "n",
		"CONFIG_FS_CONTEXT": "n",
	}
	doc, err := AnalyzeKernelReachability(kconfigDisabled, nil, cves, product, "auditor")
	if err != nil {
		t.Fatalf("AnalyzeKernelReachability failed: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}
	for _, stmt := range doc.Statements {
		if stmt.Status != StatusNotAffected {
			t.Errorf("expected %s to be not_affected, got %s", stmt.Vulnerability.Name, stmt.Status)
		}
		if stmt.Justification != JustificationVulnerableCodeNotPresent {
			t.Errorf("expected justification %s, got %s", JustificationVulnerableCodeNotPresent, stmt.Justification)
		}
	}

	// Scenario 2: CONFIG_FS_CONTEXT enabled, but symbol not in stripped ELF
	kconfigMixed := KconfigMap{
		"CONFIG_BT":         "n",
		"CONFIG_FS_CONTEXT": "y",
	}
	symbolsStripped := map[string]bool{
		"startup_64":     true,
		"sys_call_table": true,
	}
	doc2, err := AnalyzeKernelReachability(kconfigMixed, symbolsStripped, cves, product, "auditor")
	if err != nil {
		t.Fatalf("AnalyzeKernelReachability failed: %v", err)
	}
	// CVE-TEST-001 not affected via Kconfig
	if doc2.Statements[0].Status != StatusNotAffected {
		t.Errorf("expected CVE-TEST-001 not_affected, got %s", doc2.Statements[0].Status)
	}
	// CVE-TEST-002 not affected via symbol table omission
	if doc2.Statements[1].Status != StatusNotAffected {
		t.Errorf("expected CVE-TEST-002 not_affected via stripped symbols, got %s", doc2.Statements[1].Status)
	}

	// Scenario 3: CONFIG_FS_CONTEXT enabled and vulnerable symbol IS in symbol table
	symbolsVulnerable := map[string]bool{
		"legacy_parse_param": true,
	}
	doc3, err := AnalyzeKernelReachability(kconfigMixed, symbolsVulnerable, cves, product, "auditor")
	if err != nil {
		t.Fatalf("AnalyzeKernelReachability failed: %v", err)
	}
	if doc3.Statements[1].Status != StatusAffected {
		t.Errorf("expected CVE-TEST-002 to be affected, got %s", doc3.Statements[1].Status)
	}
}
