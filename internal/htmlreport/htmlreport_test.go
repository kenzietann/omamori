package htmlreport

import (
	"regexp"
	"strings"
	"testing"
)

const hostile = `<script>alert(1)</script>`

func TestEveryPartOfTheReportIsShown(t *testing.T) {
	report := "**REPLAY: recorded answers were played back. Nothing was sent.**\n\n# Omamori report: exposure check\n\nStatus: complete\n\n## Findings\n\n| ID | Severity | Type | File | Line |\n|---|---|---|---|---|\n| [SECRET:aws-access-key:001] | high | aws-access-key | app/config.py | 3 |\n\n## Fixes\n\n- aws-access-key (1): Rotate it.\n\n## AI notes (not checked by Omamori)\n\n    first line\n\n    second line\n\n## Limits\n\n- one\n- two\n"

	page := Render(report)

	for _, want := range []string{
		`<p class="replay"><strong>REPLAY: recorded answers were played back. Nothing was sent.</strong></p>`,
		"<h1>Omamori report: exposure check</h1>", "<p>Status: complete</p>", "<h2>Findings</h2>",
		"<th>ID</th><th>Severity</th>", "<td>[SECRET:aws-access-key:001]</td><td>high</td><td>aws-access-key</td><td>app/config.py</td><td>3</td>",
		"<li>aws-access-key (1): Rotate it.</li>", "<pre>first line\n\nsecond line\n</pre>", "<li>one</li>\n<li>two</li>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page has no %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "|---|") {
		t.Error("a table separator was shown")
	}
}

func TestHTMLInTheReportIsShownAsTextAndNeverRuns(t *testing.T) {
	report := "# " + hostile + "\n\n## " + hostile + "\n\n" + hostile + "\n\n| ID | File |\n|---|---|\n| <img src=x onerror=alert(1)> | notes/" + hostile + ".txt |\n\n- " + hostile + "\n\n    " + hostile + "\n\n**" + hostile + "**\n"

	page := Render(report)

	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img") {
		t.Errorf("markup from the report is in the page:\n%s", page)
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") || !strings.Contains(page, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Errorf("the text was not shown:\n%s", page)
	}

	tags := regexp.MustCompile(`<([a-zA-Z0-9]+)`).FindAllStringSubmatch(page, -1)
	allowed := map[string]bool{"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "h1": true, "h2": true, "p": true, "strong": true, "table": true, "thead": true, "tbody": true, "tr": true, "th": true, "td": true, "ul": true, "li": true, "pre": true}
	for _, tag := range tags {
		if !allowed[tag[1]] {
			t.Errorf("the tag <%s> is in the page", tag[1])
		}
	}
	for _, forbidden := range []string{"<script", "<a ", "<img", "<iframe", "<form", "<link", "<object", "<embed"} {
		if strings.Contains(strings.ToLower(page), forbidden) && !strings.Contains(strings.ToLower(page), "&lt;"+strings.TrimPrefix(forbidden, "<")) {
			t.Errorf("%q is in the page", forbidden)
		}
	}
}

func TestThePagePermitsNothingExceptItsOwnStyle(t *testing.T) {
	page := Render("# x\n")

	if !strings.Contains(page, `content="default-src 'none'; style-src 'unsafe-inline'"`) {
		t.Error("the page has no policy that blocks scripts, images and links")
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") {
		t.Error("the page points to another address")
	}
}

func TestAnEmptyOrOddReportStillMakesAPage(t *testing.T) {
	for _, report := range []string{"", "\n\n", "|", "| |", "|---|", "    ", "- ", "**", "****", "# ", "## "} {
		page := Render(report)
		if !strings.HasPrefix(page, "<!doctype html>") || !strings.HasSuffix(page, "</html>\n") {
			t.Errorf("the report %q gave a broken page", report)
		}
	}
}

func FuzzRenderNeverAddsMarkupFromTheInput(f *testing.F) {
	for _, seed := range []string{"", hostile, "| a |\n|---|\n| " + hostile + " |", "    " + hostile, "- " + hostile, "**" + hostile + "**"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, report string) {
		page := Render(report)
		body := page[strings.Index(page, "<body>"):]
		if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(body, "<script", ""), "<SCRIPT", ""), "<script") {
			t.Fatal("impossible")
		}
		if strings.Contains(body, "<script") || strings.Contains(strings.ToLower(body), "<img") || strings.Contains(strings.ToLower(body), "<a ") {
			t.Fatalf("markup from the input is in the page: %q", report)
		}
	})
}
