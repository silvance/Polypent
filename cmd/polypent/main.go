// Command polypent is the operator CLI for the PolyPent platform.
//
// All operator workflows are exposed here as a thin client of the API.
//
// Subcommands:
//
//	polypent project create  --slug <s> --name <n> --owner <o>
//	polypent project list
//	polypent scope   add|list|check
//	polypent run     create --project <id> --capabilities <c1,c2> --targets <json|host:port,...>
//	polypent run     status --run <id>
//	polypent run     cancel --run <id>
//	polypent finding list   --project <id>
//	polypent --version
//
// API location and credential come from the environment:
//
//	POLYPENT_API_URL   default http://127.0.0.1:8080
//	POLYPENT_API_TOKEN required for all /v1/* commands
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
		case "project":
			os.Exit(runProject(os.Args[2:]))
		case "scope":
			os.Exit(runScope(os.Args[2:]))
		case "run":
			os.Exit(runRun(os.Args[2:]))
		case "finding", "findings":
			os.Exit(runFinding(os.Args[2:]))
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
  %s project create  --slug <s> --name <n> --owner <o>
  %s project list
  %s scope   add     --project <uuid> --order N --effect allow|deny --kind <kind> --value <v> [flags]
  %s scope   list    --project <uuid>
  %s scope   check   --project <uuid> --kind <kind> --identity <id> [--host h] [--port p] [--url u]
  %s run     create  --project <uuid> --capabilities <c1,c2> --targets <kind=identity,...>
  %s run     status  --run <uuid>
  %s run     cancel  --run <uuid>
  %s finding list    --project <uuid> [--severity s] [--kind k]
  %s --version

Env:
  POLYPENT_API_URL    default http://127.0.0.1:8080
  POLYPENT_API_TOKEN  required for /v1/* endpoints
`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
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

// --- project subcommands ----------------------------------------------------

func runProject(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "polypent project: subcommand required (create|list)")
		return 2
	}
	switch args[0] {
	case "create":
		return runProjectCreate(args[1:])
	case "list":
		return runProjectList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "polypent project: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runProjectCreate(args []string) int {
	fs := flag.NewFlagSet("project create", flag.ContinueOnError)
	slug := fs.String("slug", "", "project slug (DNS-label-ish)")
	name := fs.String("name", "", "human-readable name")
	owner := fs.String("owner", "", "engagement lead contact")
	desc := fs.String("description", "", "freeform")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *slug == "" || *name == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "project create: --slug, --name, --owner required")
		return 2
	}
	status, body, err := apiRequest("POST", "/v1/projects", map[string]any{
		"slug": *slug, "name": *name, "owner": *owner, "description": *desc,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "create failed (%d): %s\n", status, body)
		return 1
	}
	prettyPrint(body)
	return 0
}

func runProjectList(args []string) int {
	fs := flag.NewFlagSet("project list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	status, body, err := apiRequest("GET", "/v1/projects", nil)
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

// --- run subcommands --------------------------------------------------------

func runRun(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "polypent run: subcommand required (create|status|cancel)")
		return 2
	}
	switch args[0] {
	case "create":
		return runRunCreate(args[1:])
	case "status":
		return runRunStatus(args[1:])
	case "cancel":
		return runRunCancel(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "polypent run: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runRunCreate(args []string) int {
	fs := flag.NewFlagSet("run create", flag.ContinueOnError)
	project := fs.String("project", "", "project id (uuid)")
	caps := fs.String("capabilities", "", "comma-separated collector names, e.g. http.probe,dns.passive")
	targets := fs.String("targets", "", "comma-separated kind=identity tokens, e.g. host=10.0.0.5,dns_name=example.com")
	params := fs.String("params", "", "JSON object of collector parameters (optional)")
	deadlineSec := fs.Int("deadline-seconds", 0, "per-job wall-clock deadline (0 = none)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" || *caps == "" || *targets == "" {
		fmt.Fprintln(os.Stderr, "run create: --project, --capabilities, --targets required")
		return 2
	}
	capList := splitAndTrim(*caps)
	targetList := parseTargets(*targets)
	if len(targetList) == 0 {
		fmt.Fprintln(os.Stderr, "run create: no valid targets parsed")
		return 2
	}
	body := map[string]any{
		"capabilities":     capList,
		"targets":          targetList,
		"deadline_seconds": *deadlineSec,
	}
	if *params != "" {
		var p map[string]any
		if err := json.Unmarshal([]byte(*params), &p); err != nil {
			fmt.Fprintf(os.Stderr, "run create: --params is not valid JSON: %v\n", err)
			return 2
		}
		body["parameters"] = p
	}
	status, resp, err := apiRequest("POST", "/v1/projects/"+*project+"/runs", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "run create failed (%d): %s\n", status, resp)
		return 1
	}
	prettyPrint(resp)
	return 0
}

func runRunStatus(args []string) int {
	fs := flag.NewFlagSet("run status", flag.ContinueOnError)
	runID := fs.String("run", "", "run id (uuid)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *runID == "" {
		fmt.Fprintln(os.Stderr, "run status: --run required")
		return 2
	}
	status, body, err := apiRequest("GET", "/v1/runs/"+*runID, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "get failed (%d): %s\n", status, body)
		return 1
	}
	prettyPrint(body)
	// also pull jobs
	status, jobs, err := apiRequest("GET", "/v1/runs/"+*runID+"/jobs", nil)
	if err == nil && status < 300 {
		fmt.Println("--- jobs ---")
		prettyPrint(jobs)
	}
	return 0
}

func runRunCancel(args []string) int {
	fs := flag.NewFlagSet("run cancel", flag.ContinueOnError)
	runID := fs.String("run", "", "run id (uuid)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *runID == "" {
		fmt.Fprintln(os.Stderr, "run cancel: --run required")
		return 2
	}
	status, body, err := apiRequest("POST", "/v1/runs/"+*runID+"/cancel", map[string]any{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "cancel failed (%d): %s\n", status, body)
		return 1
	}
	prettyPrint(body)
	return 0
}

// --- finding subcommands ----------------------------------------------------

func runFinding(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "polypent finding: subcommand required (list)")
		return 2
	}
	switch args[0] {
	case "list":
		return runFindingList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "polypent finding: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runFindingList(args []string) int {
	fs := flag.NewFlagSet("finding list", flag.ContinueOnError)
	project := fs.String("project", "", "project id (uuid)")
	severity := fs.String("severity", "", "filter: informational|low|medium|high|critical")
	kind := fs.String("kind", "", "filter on finding kind, e.g. info.http.live")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" {
		fmt.Fprintln(os.Stderr, "finding list: --project required")
		return 2
	}
	q := url.Values{}
	if *severity != "" {
		q.Set("severity", *severity)
	}
	if *kind != "" {
		q.Set("kind", *kind)
	}
	path := "/v1/projects/" + *project + "/findings"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	status, body, err := apiRequest("GET", path, nil)
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

// --- helpers ---------------------------------------------------------------

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTargets accepts "kind=identity" tokens; identity may include a host:port.
// "host=10.0.0.5,dns_name=example.com" → two target objects.
func parseTargets(s string) []map[string]any {
	var out []map[string]any
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		i := strings.Index(raw, "=")
		if i <= 0 {
			continue
		}
		kind := strings.TrimSpace(raw[:i])
		identity := strings.TrimSpace(raw[i+1:])
		if kind == "" || identity == "" {
			continue
		}
		t := map[string]any{"kind": kind, "identity": identity}
		// For host targets, also populate "host" so scope cidr rules can match.
		if kind == "host" {
			host := identity
			if j := strings.LastIndex(host, ":"); j > 0 && !strings.Contains(host[j:], "]") {
				host = host[:j]
			}
			t["host"] = host
		}
		out = append(out, t)
	}
	return out
}
