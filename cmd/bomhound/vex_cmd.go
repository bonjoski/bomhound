package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bonjoski/bomhound/pkg/vex"
)

func runVEX(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printVEXUsage()
		return 0
	}

	subcmd := args[0]
	switch subcmd {
	case "kernel":
		return runVEXKernel(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown vex subcommand: %s\n", subcmd)
		printVEXUsage()
		return 1
	}
}

func printVEXUsage() {
	fmt.Println(`bomhound vex — MicroVM Kernel Reachability & OpenVEX Statement Generator

Usage:
  bomhound vex kernel [flags]

Flags:
  --kconfig   Path to Linux kernel .config file
  --elf       Path to uncompressed vmlinux ELF binary (optional)
  --kallsyms  Path to /proc/kallsyms or symbol dump (optional)
  --product   Product package URL or name (default: pkg:generic/linux-microvm-kernel@unknown)
  --output    Path to output OpenVEX JSON file (default: stdout)`)
}

func runVEXKernel(args []string) int {
	fs := flag.NewFlagSet("bomhound vex kernel", flag.ContinueOnError)
	kconfigPath := fs.String("kconfig", "", "Path to Linux kernel .config file")
	elfPath := fs.String("elf", "", "Path to uncompressed vmlinux ELF binary")
	kallsymsPath := fs.String("kallsyms", "", "Path to /proc/kallsyms or symbol dump")
	product := fs.String("product", "pkg:generic/linux-microvm-kernel@unknown", "Product package URL")
	outputPath := fs.String("output", "", "Path to write OpenVEX JSON (default: stdout)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *kconfigPath == "" && *elfPath == "" && *kallsymsPath == "" {
		fmt.Fprintln(os.Stderr, "Error: at least one of --kconfig, --elf, or --kallsyms must be specified")
		return 1
	}

	var kconfig vex.KconfigMap
	if *kconfigPath != "" {
		var err error
		kconfig, err = vex.ParseKconfigFile(*kconfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Kconfig: %v\n", err)
			return 1
		}
	}

	symbols := make(map[string]bool)
	if *elfPath != "" {
		elfSyms, err := vex.ExtractELFSymbols(*elfPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed reading ELF symbols from %s: %v\n", *elfPath, err)
		} else {
			for k, v := range elfSyms {
				symbols[k] = v
			}
		}
	}

	if *kallsymsPath != "" {
		ksyms, err := vex.ParseKallsymsFile(*kallsymsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed reading kallsyms from %s: %v\n", *kallsymsPath, err)
		} else {
			for k, v := range ksyms {
				symbols[k] = v
			}
		}
	}

	doc, err := vex.AnalyzeKernelReachability(kconfig, symbols, nil, *product, "bomhound-vex / sovereign-agent-security")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing kernel reachability: %v\n", err)
		return 1
	}

	data, err := doc.ToJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing OpenVEX document: %v\n", err)
		return 1
	}

	if *outputPath != "" {
		cleanOut := filepath.Clean(*outputPath)
		if err := os.WriteFile(cleanOut, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "OpenVEX document successfully written to %s (%d statements)\n", cleanOut, len(doc.Statements))
	} else {
		fmt.Println(string(data))
	}

	return 0
}
