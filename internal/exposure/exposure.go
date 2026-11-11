package exposure

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/gitignore"
)

const Instruction = `Check this project for exposed secrets and personal data. ` +
	`Run run_detectors on the path "." first. Then explain each finding by its placeholder and suggest a fix. Do not guess any value. ` +
	`A placeholder that starts with NUMBERLIKE or EXAMPLE was judged by Omamori to be probably not real (a number inside a longer number or a name, a test value, or an example password): mention these in one short line and suggest no fix.`

var detectorLine = regexp.MustCompile(`^(.*):(\d+): (\[((?:SECRET|EXAMPLE):[a-z0-9-]+|MYNUMBER|PHONE|NUMBERLIKE):\d{3,}\])$`)

// SeverityKeptOut is for a key in an env file that .gitignore keeps out of git. It is the normal setup,
// so it is listed in its own section and is not counted as a finding.
const SeverityKeptOut = "kept-out"

// SeverityNotYours is for a match in a library or in a file that a tool made. Code of other people is
// not the responsibility of the project, and a phone-like number in it is nearly always sample text.
const SeverityNotYours = "not-yours"

// SeverityDoubtful is for a match that is most likely not real: digits inside a decimal number, a UUID or a name
// (coordinates, ids, hashes), a test value like 0123456789, or an example password like user:pass. It is hidden from
// the AI like any other match, and it is not counted.
const SeverityDoubtful = "doubtful"

type Finding struct {
	Severity    string
	Type        string
	File        string
	Line        int
	Placeholder string
	Advice      string
}

type Stats struct {
	Scans     int
	Truncated bool
	Skipped   int
	Binary    int
	Unparsed  int
}

type Collector struct {
	inner    agent.Tools
	findings map[string]Finding
	stats    Stats
}

func NewCollector(inner agent.Tools) *Collector {
	return &Collector{inner: inner, findings: make(map[string]Finding)}
}

func (collector *Collector) Call(ctx context.Context, toolName string, arguments map[string]any) (gateway.Result, error) {
	result, err := collector.inner.Call(ctx, toolName, arguments)
	if err != nil || toolName != "run_detectors" {
		return result, err
	}

	collector.stats.Scans++
	collector.stats.Skipped += result.Skipped
	collector.stats.Binary += result.Binary
	if result.Truncated {
		collector.stats.Truncated = true
	}
	collector.absorb(result.Text)

	return result, nil
}

func (collector *Collector) Stats() Stats {
	return collector.stats
}

// A file that is scanned twice gives the same lines twice. The key makes the second copy
// count as the first one. A second finding of the same type on the same line has its own
// occurrence number, so it is not lost.
func (collector *Collector) absorb(text string) {
	occurrences := make(map[string]int)

	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}

		finding, ok := parseDetectorLine(line)
		if !ok {
			collector.stats.Unparsed++
			continue
		}

		where := fmt.Sprintf("%s\x00%d\x00%s", finding.File, finding.Line, finding.Type)
		key := fmt.Sprintf("%s\x00%d", where, occurrences[where])
		occurrences[where]++

		if _, seen := collector.findings[key]; !seen {
			collector.findings[key] = finding
		}
	}
}

func parseDetectorLine(line string) (Finding, bool) {
	parts := detectorLine.FindStringSubmatch(line)
	if parts == nil {
		return Finding{}, false
	}

	lineNumber, err := strconv.Atoi(parts[2])
	if err != nil || lineNumber < 1 {
		return Finding{}, false
	}

	findingType, severity, advice := describe(parts[4])
	// A key in a local .env file is the usual place for it. It is exposed only if the file leaves the computer.
	if strings.HasPrefix(parts[4], "SECRET:") && dotenvFile(parts[1]) {
		advice = "A key in a local .env file is the normal place for it. It is exposed only if the file is committed, shared, or copied into a build or an image. Check that .gitignore lists it and that it was never committed (git log --all on the file). If it ever left your computer, revoke the key and create a new one with the smallest rights."
	}
	// Code of a library is not the responsibility of the project. Build output is the project's own, so a secret in it
	// still counts (keys do get baked into bundles), but a phone-like number or a My Number in it is sample text.
	switch {
	case libraryFile(parts[1]):
		severity, advice = SeverityNotYours, adviceNotYours
	case generatedFile(parts[1]) && (findingType == "phone" || findingType == "mynumber"):
		severity, advice = SeverityNotYours, adviceNotYours
	}

	return Finding{
		Severity:    severity,
		Type:        findingType,
		File:        parts[1],
		Line:        lineNumber,
		Placeholder: parts[3],
		Advice:      advice,
	}, true
}

func describe(label string) (findingType, severity, advice string) {
	switch {
	case label == "SECRET:aws-access-key":
		return "aws-access-key", "high", "Rotate this AWS access key in IAM, then check CloudTrail for use. Remove it from the code and from the git history. Use a secrets manager or an environment variable."
	case label == "SECRET:github-token":
		return "github-token", "high", "Revoke this token in the GitHub settings, then create a new one with the smallest scope. Remove it from the code and from the git history."
	case label == "SECRET:private-key":
		return "private-key", "high", "Treat this private key as leaked: create a new key pair and replace the old one everywhere it was used. Remove the file from the code and from the git history."
	case label == "SECRET:ai-api-key":
		return "ai-api-key", "high", "Revoke this AI provider key in the provider console, then create a new one. Check the usage page for calls you did not make. Remove it from the code and from the git history."
	case label == "SECRET:url-credentials":
		return "url-credentials", "high", "Change the password of this account. Take the password out of the address and read it from an environment variable or a secrets manager."
	case label == "SECRET:jwt":
		return "jwt", "high", "A token that is still valid can be used by anyone who has it. Revoke or let it expire, check that its signing key is not exposed, and remove it from the code."
	case strings.HasPrefix(label, "SECRET:"):
		return strings.TrimPrefix(label, "SECRET:"), "high", "Rotate this secret. Remove it from the code and from the git history."
	case label == "NUMBERLIKE":
		return "number-like", SeverityDoubtful, "These digits look like a phone number or a My Number, but they sit inside a longer number, a UUID, a table of numbers or a name, or they are a test value (digits that count up or repeat). Most likely a coordinate, a hash or an id. Not counted. Look at it with omamori peek."
	case strings.HasPrefix(label, "EXAMPLE:"):
		return strings.TrimPrefix(label, "EXAMPLE:") + " (example)", SeverityDoubtful, "The password in this address is an example from a document or a test (like user:pass). Not counted. Look at it with omamori peek."
	case label == "MYNUMBER":
		return "mynumber", "high", "This is a possible My Number (the check digit is valid). Remove it from the file. Check if the file is shared or kept in version control."
	}

	return "phone", "medium", "This looks like a Japanese phone number. Remove it if it belongs to a person."
}

// dotenvFile says whether a path is an environment file like .env or .env.production.
func dotenvFile(path string) bool {
	name := path[strings.LastIndex(path, "/")+1:]

	return name == ".env" || strings.HasPrefix(name, ".env.") && !strings.HasSuffix(name, ".example") && !strings.HasSuffix(name, ".sample")
}

const adviceNotYours = "This is in a library, a cache, or a file that a tool made, not in your own code. It is not counted. If you want to be sure, look at the match with omamori peek."

var libraryFolders = map[string]bool{
	"deps": true, "bower_components": true, "site-packages": true, "third_party": true, "third-party": true,
	"jspm_packages": true, ".yarn": true, ".pnpm-store": true, ".angular": true, ".cache": true, ".parcel-cache": true,
	".turbo": true, ".gradle": true,
}

// Folders of AI coding tools hold plugins and skills that other people wrote. Their settings files stay yours.
var toolFolders = map[string]bool{".agents": true, ".claude": true, ".codex": true, ".gemini": true, ".cursor": true, ".windsurf": true}

var toolPluginFolders = map[string]bool{"skills": true, "plugins": true, "extensions": true, "marketplace": true}

// libraryFile says whether a path is code of another project or a cache of it.
func libraryFile(path string) bool {
	parts := strings.Split(path, "/")
	folders := parts[:len(parts)-1]
	for index, folder := range folders {
		if libraryFolders[folder] {
			return true
		}
		if toolFolders[folder] && index+1 < len(folders) && toolPluginFolders[folders[index+1]] {
			return true
		}
	}

	return false
}

var generatedFolders = map[string]bool{
	"dist": true, "build": true, "out": true, ".next": true, ".nuxt": true, ".svelte-kit": true,
	"coverage": true, "playwright-report": true, "test-results": true, "storybook-static": true, "target": true,
}

var generatedSuffixes = []string{".map", ".min.js", ".min.css", ".bundle.js"}

// generatedFile says whether a path is build output, a cache or a report that a tool made.
func generatedFile(path string) bool {
	parts := strings.Split(path, "/")
	for _, folder := range parts[:len(parts)-1] {
		if generatedFolders[folder] {
			return true
		}
	}

	name := parts[len(parts)-1]
	for _, suffix := range generatedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

func severityRank(severity string) int {
	switch severity {
	case "high":
		return 0
	case "low":
		return 2
	case SeverityKeptOut:
		return 3
	case SeverityNotYours:
		return 4
	case SeverityDoubtful:
		return 5
	}

	return 1
}

func (collector *Collector) Findings() []Finding {
	found := make([]Finding, 0, len(collector.findings))
	for _, finding := range collector.findings {
		found = append(found, finding)
	}

	slices.SortFunc(found, func(first, second Finding) int {
		return cmp.Or(
			cmp.Compare(severityRank(first.Severity), severityRank(second.Severity)),
			cmp.Compare(first.File, second.File),
			cmp.Compare(first.Line, second.Line),
			cmp.Compare(first.Placeholder, second.Placeholder),
		)
	})

	return found
}

type Runner interface {
	Run(ctx context.Context, instruction string) agent.Outcome
}

func Run(ctx context.Context, runner Runner, collector *Collector) (string, agent.Outcome, error) {
	outcome := runner.Run(ctx, Instruction)
	collector.Complete(ctx)
	collector.CheckIgnore(ctx)
	report, err := Render(collector.Findings(), collector.Stats(), outcome)

	return report, outcome, err
}

const (
	adviceIgnoredEnv = "Your .gitignore keeps this file out of git, which is the right setup. Nothing to fix today, but Omamori cannot see the git history: check with git log --all --oneline on the file, and if it prints a commit, the key is in the history, so revoke it. Keep the rights of the key small, and revoke the key if the file ever left your computer."
	adviceOpenEnv    = "No .gitignore rule in the scanned folder keeps this file out of git. A commit would publish the key. Add the file to .gitignore, check that it was never committed, and revoke the key and create a new one if it was."
)

// CheckIgnore reads the .gitignore files above each env file that holds a secret, with the same read-only
// tools, and sets the severity. A key in an env file that git ignores is the normal case (medium). A key in
// an env file that git does not ignore is one commit away from being published (high). If a .gitignore
// cannot be read, the finding keeps its first advice, which also says to check.
func (collector *Collector) CheckIgnore(ctx context.Context) {
	layers := make(map[string]*gitignore.Layer)
	unknown := make(map[string]bool)

	for key, finding := range collector.findings {
		if !strings.HasPrefix(finding.Placeholder, "[SECRET:") || !dotenvFile(finding.File) {
			continue
		}

		var chain []gitignore.Layer
		readable := true
		for _, dir := range directoriesAbove(finding.File) {
			if unknown[dir] {
				readable = false
				break
			}
			if _, loaded := layers[dir]; !loaded {
				layer, ok := collector.readLayer(ctx, dir)
				if !ok {
					unknown[dir] = true
					readable = false
					break
				}
				layers[dir] = layer
			}
			if layers[dir] != nil {
				chain = append(chain, *layers[dir])
			}
		}
		if !readable {
			continue
		}

		if gitignore.Ignored(chain, finding.File) {
			finding.Severity, finding.Advice = SeverityKeptOut, adviceIgnoredEnv
		} else {
			finding.Severity, finding.Advice = "high", adviceOpenEnv
		}
		collector.findings[key] = finding
	}
}

// directoriesAbove lists the folders of a path from the project folder down: "" then "a" then "a/b".
func directoriesAbove(path string) []string {
	dirs := []string{""}
	parts := strings.Split(path, "/")
	for count := 1; count < len(parts); count++ {
		dirs = append(dirs, strings.Join(parts[:count], "/"))
	}

	return dirs
}

// readLayer returns the rules of the .gitignore in one folder. A nil layer with true means that there is
// none. False means that it could not be found out.
func (collector *Collector) readLayer(ctx context.Context, dir string) (*gitignore.Layer, bool) {
	folder := dir
	if folder == "" {
		folder = "."
	}

	listing, err := collector.inner.Call(ctx, "list_dir", map[string]any{"path": folder})
	if err != nil {
		return nil, false
	}
	if !slices.Contains(strings.Split(listing.Text, "\n"), ".gitignore") && !listing.Truncated {
		return nil, true
	}

	read, err := collector.inner.Call(ctx, "read_file", map[string]any{"path": strings.TrimPrefix(dir+"/.gitignore", "/")})
	if err != nil {
		return nil, !slices.Contains(strings.Split(listing.Text, "\n"), ".gitignore")
	}

	return &gitignore.Layer{Dir: dir, Rules: gitignore.Parse(read.Text)}, true
}

// fullScanner is what the gateway offers to finish a scan that stopped at a limit.
type fullScanner interface {
	FullScan(ctx context.Context, path string) (gateway.Result, error)
}

// Complete finishes the scan. The answer of run_detectors to the AI is short on purpose, and it stops at a number of
// results and of files. When it stopped, the findings of the folders that come after the stop would be missing, and the
// report would look cleaner than the project is. So the report uses a scan of the whole project without those caps.
// If that scan cannot be done, or reaches its own cap, the report keeps what it has and says so.
func (collector *Collector) Complete(ctx context.Context) {
	scanner, able := collector.inner.(fullScanner)
	if !able || !collector.stats.Truncated || ctx.Err() != nil {
		return
	}

	result, err := scanner.FullScan(ctx, ".")
	if err != nil {
		return
	}

	collector.findings = make(map[string]Finding)
	collector.stats.Unparsed = 0
	collector.stats.Skipped = result.Skipped
	collector.stats.Binary = result.Binary
	collector.stats.Truncated = result.Truncated
	collector.absorb(result.Text)
}
