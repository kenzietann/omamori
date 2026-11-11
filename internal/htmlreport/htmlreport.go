// Package htmlreport turns the Markdown report into one static HTML page (FR-17).
// Text from scanned files can reach the report (file names, AI notes), so every character is escaped.
// The page has no script, no link, no image and no form, and a policy that blocks all of them.
package htmlreport

import (
	"html"
	"strings"
)

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Omamori report</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1b1b;background:#fff}
h1,h2{line-height:1.2}
table{border-collapse:collapse;margin:1rem 0;width:100%}
th,td{border:1px solid #bbb;padding:.35rem .6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f0f0f0}
pre{background:#f6f6f6;padding:.75rem;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}
.replay{background:#fff3cd;border:1px solid #d4a72c;padding:.5rem .75rem}
@media (prefers-color-scheme: dark){body{color:#e6e6e6;background:#161616}th{background:#2a2a2a}th,td{border-color:#555}pre{background:#222}.replay{background:#3a3000;border-color:#a88a00}}
</style>
</head>
<body>
`

// Render makes the page. The input is the report of Omamori. Anything it does not know is shown as plain text.
func Render(report string) string {
	var out strings.Builder
	out.WriteString(page)

	lines := strings.Split(strings.ReplaceAll(report, "\r\n", "\n"), "\n")
	inList, inTable, inCode := false, false, false
	closeBlocks := func() {
		if inList {
			out.WriteString("</ul>\n")
			inList = false
		}
		if inTable {
			out.WriteString("</tbody></table>\n")
			inTable = false
		}
		if inCode {
			out.WriteString("</pre>\n")
			inCode = false
		}
	}

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "    "):
			if !inCode {
				closeBlocks()
				out.WriteString("<pre>")
				inCode = true
			} else {
				out.WriteString("\n")
			}
			out.WriteString(html.EscapeString(strings.TrimPrefix(line, "    ")))
		case inCode && strings.TrimSpace(line) == "":
			out.WriteString("\n")
		case strings.HasPrefix(line, "# "):
			closeBlocks()
			out.WriteString("<h1>" + html.EscapeString(line[2:]) + "</h1>\n")
		case strings.HasPrefix(line, "## "):
			closeBlocks()
			out.WriteString("<h2>" + html.EscapeString(line[3:]) + "</h2>\n")
		case strings.HasPrefix(line, "|"):
			cells := splitRow(line)
			if isSeparator(cells) {
				continue
			}
			if !inTable {
				closeBlocks()
				out.WriteString("<table><thead><tr>" + rowOf("th", cells) + "</tr></thead><tbody>\n")
				inTable = true
				continue
			}
			out.WriteString("<tr>" + rowOf("td", cells) + "</tr>\n")
		case strings.HasPrefix(line, "- "):
			if !inList {
				closeBlocks()
				out.WriteString("<ul>\n")
				inList = true
			}
			out.WriteString("<li>" + html.EscapeString(line[2:]) + "</li>\n")
		case strings.TrimSpace(line) == "":
			closeBlocks()
		case strings.HasPrefix(line, "**") && strings.HasSuffix(line, "**") && len(line) > 4:
			closeBlocks()
			out.WriteString(`<p class="replay"><strong>` + html.EscapeString(line[2:len(line)-2]) + "</strong></p>\n")
		default:
			closeBlocks()
			out.WriteString("<p>" + html.EscapeString(line) + "</p>\n")
		}
	}
	closeBlocks()
	out.WriteString("</body>\n</html>\n")

	return out.String()
}

func splitRow(line string) []string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "|"), "|")
	cells := strings.Split(trimmed, "|")
	for index := range cells {
		cells[index] = strings.TrimSpace(cells[index])
	}

	return cells
}

func isSeparator(cells []string) bool {
	for _, cell := range cells {
		if strings.Trim(cell, "-: ") != "" {
			return false
		}
	}

	return len(cells) > 0
}

func rowOf(tag string, cells []string) string {
	var out strings.Builder
	for _, cell := range cells {
		out.WriteString("<" + tag + ">" + html.EscapeString(cell) + "</" + tag + ">")
	}

	return out.String()
}
