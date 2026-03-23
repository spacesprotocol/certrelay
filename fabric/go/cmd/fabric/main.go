package main

import (
	"fmt"
	"os"
	"strings"

	fabric "github.com/spacesprotocol/fabric-go"
	libveritas "github.com/spacesprotocol/libveritas-go"
)

func main() {
	args := os.Args[1:]
	var handles []string
	var seeds []string
	var anchorSetHash string
	devMode := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--seeds":
			i++
			if i >= len(args) {
				exitUsage("--seeds requires a value")
			}
			seeds = strings.Split(args[i], ",")
		case "--anchor-set-hash":
			i++
			if i >= len(args) {
				exitUsage("--anchor-set-hash requires a value")
			}
			anchorSetHash = args[i]
		case "--dev-mode":
			devMode = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(args[i], "-") {
				exitUsage("unknown option: " + args[i])
			}
			handles = append(handles, args[i])
		}
	}

	if len(handles) == 0 {
		exitUsage("no handles specified")
	}

	if len(seeds) == 0 {
		seeds = fabric.DefaultSeeds
	}

	f := fabric.New(seeds)
	if devMode {
		f.SetDevMode(true)
	}
	if anchorSetHash != "" {
		f.SetAnchorSetHash(anchorSetHash)
	}

	zones, err := f.ResolveAll(handles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	zoneMap := make(map[string]libveritas.Zone)
	for _, z := range zones {
		if _, exists := zoneMap[z.Handle]; !exists {
			zoneMap[z.Handle] = z
		}
	}

	for _, handle := range handles {
		z, ok := zoneMap[handle]
		if !ok {
			fmt.Fprintf(os.Stderr, "%s: not found\n", handle)
			continue
		}
		j, err := libveritas.ZoneToJson(z)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", handle, err)
			continue
		}
		fmt.Println(j)
	}
}

func printUsage() {
	fmt.Println(`Usage: fabric [options] <handle> [<handle> ...]

Resolve handles via the certrelay network.

Options:
  --seeds <url,url,...>      Seed relay URLs (comma-separated)
  --anchor-set-hash <hex>    Anchor set hash for verification
  --dev-mode                 Enable dev mode (skip finality checks)
  -h, --help                 Show this help`)
}

func exitUsage(msg string) {
	fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	printUsage()
	os.Exit(1)
}
