package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/outbound"
)

type countingProvider struct{ requests int }

func (provider *countingProvider) Name() string { return "FakeAI" }

func (provider *countingProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	provider.requests++

	return outbound.Response{Text: "BEGIN_CLAIMS\n[]\nEND_CLAIMS", TokensUsed: 50}, nil
}

func evalEnvironment(provider *countingProvider, output string, stdout, stderr *bytes.Buffer) environment {
	return environment{
		stdout: stdout, stderr: stderr,
		lookupEnv:   func(name string) string { return map[string]string{"OPENAI_API_KEY": commandKey}[name] },
		home:        homeAt(output),
		now:         func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC) },
		newProvider: func(id, key, model, reasoning string) (outbound.Provider, error) { return provider, nil },
	}
}

func TestEvalSendsNothingWithoutAgreement(t *testing.T) {
	provider := &countingProvider{}
	var stdout, stderr bytes.Buffer
	args := []string{"eval", "--provider", "openai", "--fixtures", "../../testdata/fixtures"}

	code := run(args, evalEnvironment(provider, t.TempDir(), &stdout, &stderr))

	if code != exitUsage || provider.requests != 0 || !strings.Contains(stderr.String(), "nothing was sent. Add --yes") || !strings.Contains(stdout.String(), "Cost cap: 600000 tokens") {
		t.Errorf("code %d, requests %d, stdout %q, stderr %q", code, provider.requests, stdout.String(), stderr.String())
	}
}

func TestEvalRunsTheSeriesAndSavesTheTable(t *testing.T) {
	provider := &countingProvider{}
	output := t.TempDir()
	var stdout, stderr bytes.Buffer
	args := []string{"eval", "--yes", "--runs", "1", "--provider", "openai", "--model", "fake-model", "--fixtures", "../../testdata/fixtures"}

	code := run(args, evalEnvironment(provider, output, &stdout, &stderr))

	if code != exitOK || provider.requests == 0 {
		t.Fatalf("code %d, requests %d, stderr %q", code, provider.requests, stderr.String())
	}
	for _, want := range []string{"Task B: benign.log, run 1 of 1: passed", "| Task B: benign.log | 1 of 1 |", "Model: fake-model", "Saved to:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), commandKey) {
		t.Error("the key was printed")
	}
	files, _ := filepath.Glob(filepath.Join(output, "omamori-output", "live-*", "live-results-*.md"))
	if len(files) != 1 {
		t.Errorf("results files: %v", files)
	} else if data, _ := os.ReadFile(files[0]); !strings.Contains(string(data), "Omamori live test results") {
		t.Error("the results file is wrong")
	}
}

func TestEvalRefusesBadArguments(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want string
	}{
		{"no provider", []string{"eval", "--yes"}, "choose a known provider"},
		{"an unknown provider", []string{"eval", "--yes", "--provider", "nope"}, "choose a known provider"},
		{"zero runs", []string{"eval", "--yes", "--provider", "openai", "--runs", "0"}, "above 0"},
		{"an extra argument", []string{"eval", "--yes", "--provider", "openai", "extra"}, "usage: omamori eval"},
		{"no fixtures", []string{"eval", "--yes", "--provider", "openai", "--fixtures", "/nonexistent-folder"}, "expected findings"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &countingProvider{}
			var stdout, stderr bytes.Buffer

			code := run(testCase.args, evalEnvironment(provider, t.TempDir(), &stdout, &stderr))

			if code == exitOK || provider.requests != 0 || !strings.Contains(stderr.String(), testCase.want) {
				t.Errorf("code %d, requests %d, stderr %q", code, provider.requests, stderr.String())
			}
		})
	}
}
