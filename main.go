package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type IOC struct {
	IOC     string `json:"ioc"`
	Type    string `json:"ioc_type"` // ip|domain|url|hash
	SHA256  string `json:"sha256"`   // fingerprint of normalized key
	Source  string `json:"source"`   // file name or stdin
	Context string `json:"context"`  // optional: line snippet
}

var (
	reURL  = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>()[\]]+`)
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reHash = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b`)
	reDom  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b`)
)

func main() {
	inPath := flag.String("in", "", "Input file path (ignored if --stdin)")
	outPrefix := flag.String("out", "iocs", "Output prefix (default: iocs)")
	useStdin := flag.Bool("stdin", false, "Read input from stdin")
	maxContext := flag.Int("context", 120, "Max context chars to store per IOC (default: 120)")
	flag.Parse()

	var r io.Reader
	sourceName := ""

	if *useStdin {
		r = os.Stdin
		sourceName = "stdin"
	} else {
		if strings.TrimSpace(*inPath) == "" {
			fmt.Fprintln(os.Stderr, "Usage: ioc-extractor-go -in input.txt [-out iocs]")
			fmt.Fprintln(os.Stderr, "   or: cat input.txt | ioc-extractor-go --stdin")
			os.Exit(2)
		}
		f, err := os.Open(*inPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to open input:", err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
		sourceName = filepath.Base(*inPath)
	}

	iocs := extractIOCs(r, sourceName, *maxContext)

	// stable ordering
	sort.Slice(iocs, func(i, j int) bool {
		if iocs[i].Type != iocs[j].Type {
			return iocs[i].Type < iocs[j].Type
		}
		return strings.ToLower(iocs[i].IOC) < strings.ToLower(iocs[j].IOC)
	})

	csvPath := *outPrefix + ".csv"
	jsonPath := *outPrefix + ".json"

	if err := writeCSV(csvPath, iocs); err != nil {
		fmt.Fprintln(os.Stderr, "CSV write error:", err)
		os.Exit(1)
	}
	if err := writeJSON(jsonPath, iocs); err != nil {
		fmt.Fprintln(os.Stderr, "JSON write error:", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d unique IOCs\n", len(iocs))
	fmt.Println("CSV :", csvPath)
	fmt.Println("JSON:", jsonPath)
}

func extractIOCs(r io.Reader, source string, maxCtx int) []IOC {
	sc := bufio.NewScanner(r)
	// allow longer lines
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	seen := make(map[string]struct{})
	out := make([]IOC, 0, 256)

	for sc.Scan() {
		line := sc.Text()
		lineNorm := normalize(line)

		cands := findCandidates(lineNorm)
		for _, cand := range cands {
			c := normalize(cand)
			t := classify(c)
			if t == "" {
				continue
			}

			key := makeKey(t, c)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			ctx := lineNorm
			if maxCtx > 0 && len(ctx) > maxCtx {
				ctx = ctx[:maxCtx] + "..."
			}

			out = append(out, IOC{
				IOC:     c,
				Type:    t,
				SHA256:  sha256Hex(key),
				Source:  source,
				Context: ctx,
			})
		}
	}

	// ignore scanner error? better to surface
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Read error:", err)
	}

	return out
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'<>(),;`)
	// common deobfuscation patterns in CTI reports
	s = strings.ReplaceAll(s, "hxxp://", "http://")
	s = strings.ReplaceAll(s, "hxxps://", "https://")
	s = strings.ReplaceAll(s, "[.]", ".")
	s = strings.ReplaceAll(s, "(.)", ".")
	return s
}

func findCandidates(text string) []string {
	var out []string

	for _, m := range reURL.FindAllString(text, -1) {
		out = append(out, m)
	}
	for _, m := range reIPv4.FindAllString(text, -1) {
		out = append(out, m)
	}
	for _, m := range reHash.FindAllString(text, -1) {
		out = append(out, m)
	}
	for _, m := range reDom.FindAllString(text, -1) {
		out = append(out, m)
	}

	return out
}

func classify(ioc string) string {
	ioc = strings.TrimSpace(ioc)
	if ioc == "" {
		return ""
	}
	// URL first
	if reURL.MatchString(ioc) || strings.HasPrefix(strings.ToLower(ioc), "http://") || strings.HasPrefix(strings.ToLower(ioc), "https://") {
		return "url"
	}
	// Hash
	if reHash.MatchString(ioc) && (len(ioc) == 32 || len(ioc) == 40 || len(ioc) == 64) {
		return "hash"
	}
	// IP (validate)
	if reIPv4.MatchString(ioc) {
		ip := net.ParseIP(ioc)
		if ip != nil && ip.To4() != nil {
			return "ip"
		}
		return ""
	}
	// Domain (avoid emails)
	if strings.Contains(ioc, "@") {
		return ""
	}
	if reDom.MatchString(ioc) {
		return "domain"
	}
	return ""
}

func makeKey(t, ioc string) string {
	// normalize for dedupe: domains/urls to lower-case
	switch t {
	case "domain", "url":
		return t + "|" + strings.ToLower(ioc)
	default:
		return t + "|" + ioc
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeCSV(path string, iocs []IOC) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{"ioc_type", "ioc", "sha256", "source", "context"})
	for _, x := range iocs {
		_ = w.Write([]string{x.Type, x.IOC, x.SHA256, x.Source, x.Context})
	}
	return w.Error()
}

func writeJSON(path string, iocs []IOC) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(iocs)
}
