// Command polypent is the operator CLI for the PolyPent platform.
//
// Subcommands:
//
//	polypent scope add    --project <uuid> --kind <kind> --value <v> ...
//	polypent scope list   --project <uuid>
//	polypent scope check  --project <uuid> --kind <kind> --identity <id> ...
//	polypent --version
//
// API location and credential come from the environment:
//
//	POLYPENT_API_URL   default http://127.0.0.1:8080
//	POLYPENT_API_TOKEN required for all scope commands
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/silvance/polypent/internal/version"
)

const binaryName = "polypent"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Println(version.String(binaryName))
			return
		case "scope":
			os.Exit(runScope(os.Args[2:]))
		case "-h", "--help", "help":
			printUsage(os.Stdout)
			return
		}
	}
	printUsage(os.Stderr)
	os.Exit(2)
}

func printUsage(w *os.File) {
	_, _ = fmt.Fprintf(w, `polypent — PolyPent operator CLI

Usage:
  %s scope add    --project <uuid> --order N --effect allow|deny --kind <kind> --value <v> [flags]
  %s scope list   --project <uuid>
  %s scope check  --project <uuid> --kind <kind> --identity <id> [--host h] [--port p] [--url u]
  %s --version

Env:
  POLYPENT_API_URL    default http://127.0.0.1:8080
  POLYPENT_API_TOKEN  required for /v1/* endpoints
`, binaryName, binaryName, binaryName, binaryName)
}

func runScope(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "polypent scope: subcommand required (add|list|check)")
		return 2
	}
	switch args[0] {
	case "add":
		return runScopeAdd(args[1:])
	case "list":
		return runScopeList(args[1:])
	case "check":
		return runScopeCheck(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "polypent scope: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runScopeAdd(args []string) int {
	fs := flag.NewFlagSet("scope add", flag.ContinueOnError)
	project := fs.String("project", "", "project id (uuid)")
	order := fs.Int("order", 0, "rule order; lower wins")
	effect := fs.String("effect", "allow", "allow|deny|out_of_scope")
	kind := fs.String("kind", "", "rule kind (cidr, host, dns_exact, dns_wildcard, dns_suffix, url_prefix, path_glob, vhost, account)")
	value := fs.String("value", "", "match value")
	portMin := fs.Int("port-min", 0, "lower bound of port range (0 = any)")
	portMax := fs.Int("port-max", 0, "upper bound of port range")
	maxConcurrent := fs.Int("max-concurrent", 0, "advisory max concurrent requests")
	maxRPS := fs.Float64("max-rps", 0, "advisory max requests per second")
	note := fs.String("note", "", "operator note")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" || *kind == "" || *value == "" {
		fmt.Fprintln(os.Stderr, "scope add: --project, --kind, and --value are required")
		return 2
	}
	body := map[string]any{
		"order": *order, "effect": *effect, "kind": *kind, "value": *value,
		"port_min": *portMin, "port_max": *portMax,
		"max_concurrent": *maxConcurrent, "max_rps": *maxRPS,
		"note": *note,
	}
	status, respBody, err := apiRequest("POST", "/v1/projects/"+*project+"/scope", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "create failed (%d): %s\n", status, respBody)
		return 1
	}
	prettyPrint(respBody)
	return 0
}

func runScopeList(args []string) int {
	fs := flag.NewFlagSet("scope list", flag.ContinueOnError)
	project := fs.String("project", "", "project id (uuid)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" {
		fmt.Fprintln(os.Stderr, "scope list: --project required")
		return 2
	}
	status, body, err := apiRequest("GET", "/v1/projects/"+*project+"/scope", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "list failed (%d): %s\n", status, body)
		return 1
	}
	prettyPrint(body)
	return 0
}

func runScopeCheck(args []string) int {
	fs := flag.NewFlagSet("scope check", flag.ContinueOnError)
	project := fs.String("project", "", "project id (uuid)")
	kind := fs.String("kind", "", "target kind (host, dns_name, url, account)")
	identity := fs.String("identity", "", "target identity")
	host := fs.String("host", "", "structured host (optional)")
	port := fs.Int("port", 0, "port (optional)")
	url := fs.String("url", "", "absolute URL (for url targets)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" || *kind == "" || *identity == "" {
		fmt.Fprintln(os.Stderr, "scope check: --project, --kind, --identity required")
		return 2
	}
	body := map[string]any{
		"kind": *kind, "identity": *identity,
		"host": *host, "port": *port, "url": *url,
	}
	status, resp, err := apiRequest("POST", "/v1/projects/"+*project+"/scope/check", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "check failed (%d): %s\n", status, resp)
		return 1
	}
	prettyPrint(resp)
	return 0
}

// apiRequest issues an authenticated JSON request and returns
// (status, response body bytes, err).
func apiRequest(method, path string, body any) (int, []byte, error) {
	base := os.Getenv("POLYPENT_API_URL")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	tok := os.Getenv("POLYPENT_API_TOKEN")
	if tok == "" {
		return 0, nil, errors.New("POLYPENT_API_TOKEN must be set")
	}
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(base, "/")+path, buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, b, nil
}

func prettyPrint(raw []byte) {
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		fmt.Println(string(raw))
		return
	}
	out, err := json.MarshalIndent(any, "", "  ")
	if err != nil {
		fmt.Println(string(raw))
		return
	}
	fmt.Println(string(out))
}
