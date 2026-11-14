package vex

import (
	"fmt"
	"strings"
)

// KernelCVE models a specific vulnerability and its prerequisite Kconfig and ELF symbols.
type KernelCVE struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Subsystem         string   `json:"subsystem"`
	RequiredKconfig   []string `json:"required_kconfig"`
	VulnerableSymbols []string `json:"vulnerable_symbols"`
}

// DefaultKernelCVECatalog returns standard Linux kernel CVEs frequently triggering
// false positives on stripped microVM and embedded kernels.
func DefaultKernelCVECatalog() []KernelCVE {
	return []KernelCVE{
		{
			ID:                "CVE-2021-3564",
			Title:             "Bluetooth L2CAP double-free vulnerability",
			Subsystem:         "Bluetooth",
			RequiredKconfig:   []string{"CONFIG_BT"},
			VulnerableSymbols: []string{"hci_sock_bind", "l2cap_chan_connect"},
		},
		{
			ID:                "CVE-2022-25636",
			Title:             "Netfilter nf_tables heap out-of-bounds write",
			Subsystem:         "Netfilter",
			RequiredKconfig:   []string{"CONFIG_NF_TABLES", "CONFIG_NETFILTER"},
			VulnerableSymbols: []string{"nft_fwd_dup_netdev_offload", "nft_rule_expr_deactivate"},
		},
		{
			ID:                "CVE-2021-34866",
			Title:             "eBPF ringbuf verification bypass",
			Subsystem:         "eBPF",
			RequiredKconfig:   []string{"CONFIG_BPF_SYSCALL"},
			VulnerableSymbols: []string{"bpf_link_get_from_fd", "bpf_ringbuf_reserve"},
		},
		{
			ID:                "CVE-2022-0185",
			Title:             "Legacy filesystem parameter parsing buffer overflow",
			Subsystem:         "VFS",
			RequiredKconfig:   []string{"CONFIG_FS_CONTEXT"},
			VulnerableSymbols: []string{"legacy_parse_param"},
		},
		{
			ID:                "CVE-2023-32233",
			Title:             "Netfilter nf_tables use-after-free",
			Subsystem:         "Netfilter",
			RequiredKconfig:   []string{"CONFIG_NF_TABLES"},
			VulnerableSymbols: []string{"nf_tables_deactivate_set", "nft_lookup_init"},
		},
		{
			ID:                "CVE-2022-1015",
			Title:             "Netfilter nf_tables out-of-bounds write in expression register validation",
			Subsystem:         "Netfilter",
			RequiredKconfig:   []string{"CONFIG_NF_TABLES"},
			VulnerableSymbols: []string{"nft_parse_register_load", "nft_validate_register_load"},
		},
		{
			ID:                "CVE-2020-14386",
			Title:             "AF_PACKET ring buffer memory corruption",
			Subsystem:         "Networking",
			RequiredKconfig:   []string{"CONFIG_PACKET"},
			VulnerableSymbols: []string{"tpacket_rcv", "packet_set_ring"},
		},
		{
			ID:                "CVE-2022-2602",
			Title:             "io_uring register buffer use-after-free",
			Subsystem:         "io_uring",
			RequiredKconfig:   []string{"CONFIG_IO_URING"},
			VulnerableSymbols: []string{"io_uring_setup", "io_sq_thread"},
		},
		{
			ID:                "CVE-2021-22555",
			Title:             "Netfilter x_tables 32-bit compat heap out-of-bounds write",
			Subsystem:         "Netfilter",
			RequiredKconfig:   []string{"CONFIG_NETFILTER_XTABLES"},
			VulnerableSymbols: []string{"compat_do_replace", "xt_compat_target_to_user"},
		},
		{
			ID:                "CVE-2023-31436",
			Title:             "QFQ network scheduler out-of-bounds write",
			Subsystem:         "QoS",
			RequiredKconfig:   []string{"CONFIG_NET_SCH_QFQ"},
			VulnerableSymbols: []string{"qfq_enqueue", "qfq_update_class"},
		},
		{
			ID:                "CVE-2022-32250",
			Title:             "Netfilter nf_tables set element use-after-free",
			Subsystem:         "Netfilter",
			RequiredKconfig:   []string{"CONFIG_NF_TABLES"},
			VulnerableSymbols: []string{"nft_set_elem_init"},
		},
		{
			ID:                "CVE-2020-0431",
			Title:             "USB keyboard HID device driver memory corruption",
			Subsystem:         "USB",
			RequiredKconfig:   []string{"CONFIG_USB", "CONFIG_USB_SUPPORT"},
			VulnerableSymbols: []string{"kempld_kbd_probe"},
		},
	}
}

// ReachabilityResult holds the outcome of analyzing a single kernel vulnerability.
type ReachabilityResult struct {
	CVE             KernelCVE
	Status          string
	Justification   string
	ImpactStatement string
}

// AnalyzeKernelReachability evaluates a list of CVEs against a parsed Kconfig map
// and an extracted symbol map, generating an OpenVEX document.
func AnalyzeKernelReachability(
	kconfig KconfigMap,
	symbols map[string]bool,
	cves []KernelCVE,
	productPurl string,
	author string,
) (*OpenVEXDocument, error) {
	if len(cves) == 0 {
		cves = DefaultKernelCVECatalog()
	}
	if productPurl == "" {
		productPurl = "pkg:generic/linux-microvm-kernel@unknown"
	}

	doc := NewOpenVEXDocument(author)

	for _, cve := range cves {
		stmt := evaluateCVE(cve, kconfig, symbols, productPurl)
		doc.Statements = append(doc.Statements, stmt)
	}

	return doc, nil
}

func evaluateCVE(cve KernelCVE, kconfig KconfigMap, symbols map[string]bool, product string) Statement {
	// Rule 1: Check Kconfig preconditions
	if len(cve.RequiredKconfig) > 0 && len(kconfig) > 0 {
		var missingConfigs []string
		for _, cfg := range cve.RequiredKconfig {
			if !kconfig.IsEnabled(cfg) {
				missingConfigs = append(missingConfigs, cfg)
			}
		}

		if len(missingConfigs) > 0 {
			return Statement{
				Vulnerability: VulnerabilityIdent{
					Name:        cve.ID,
					Description: cve.Title,
				},
				Products:      []string{product},
				Status:        StatusNotAffected,
				Justification: JustificationVulnerableCodeNotPresent,
				ImpactStatement: fmt.Sprintf(
					"Subsystem %s disabled: required kernel configuration %s not enabled in .config.",
					cve.Subsystem,
					strings.Join(missingConfigs, ", "),
				),
			}
		}
	}

	// Rule 2: Check ELF / kallsyms symbol table
	if len(symbols) > 0 && len(cve.VulnerableSymbols) > 0 {
		var foundSymbols []string
		for _, sym := range cve.VulnerableSymbols {
			if symbols[sym] {
				foundSymbols = append(foundSymbols, sym)
			}
		}

		if len(foundSymbols) == 0 {
			return Statement{
				Vulnerability: VulnerabilityIdent{
					Name:        cve.ID,
					Description: cve.Title,
				},
				Products:      []string{product},
				Status:        StatusNotAffected,
				Justification: JustificationVulnerableCodeNotPresent,
				ImpactStatement: fmt.Sprintf(
					"Vulnerable functions (%s) are not present in the stripped kernel image symbol table.",
					strings.Join(cve.VulnerableSymbols, ", "),
				),
			}
		}

		// Symbols ARE present in the image
		return Statement{
			Vulnerability: VulnerabilityIdent{
				Name:        cve.ID,
				Description: cve.Title,
			},
			Products: []string{product},
			Status:   StatusAffected,
			ImpactStatement: fmt.Sprintf(
				"Vulnerable function(s) %s detected in kernel symbol table.",
				strings.Join(foundSymbols, ", "),
			),
		}
	}

	// Rule 3: Insufficient telemetry to prove negative
	return Statement{
		Vulnerability: VulnerabilityIdent{
			Name:        cve.ID,
			Description: cve.Title,
		},
		Products:        []string{product},
		Status:          StatusUnderInvestigation,
		ImpactStatement: "Kernel configuration or symbol tables were insufficient to conclusively prove absence of vulnerable code.",
	}
}
