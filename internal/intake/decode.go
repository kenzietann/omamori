package intake

import (
	"regexp"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// Fields that are derived from a request, so the web rules also see what the server sees after decoding. The
// decoded ones are added only when they differ from the value as written, so an ordinary request carries none.
const (
	// URLDecoded is the URL percent-decoded up to maxDecodes times, "+" read as a space, with SQL comments as
	// spaces: "%2527%2520OR" becomes "' OR", and "1/**/OR/**/1" becomes "1 OR 1".
	URLDecoded = "url_decoded"
	// URLCompact is URLDecoded with comments and spaces removed, so a keyword that a comment splits is whole
	// again: "UN/**/ION/**/SEL/**/ECT" becomes "UNIONSELECT".
	URLCompact = "url_compact"
	// URLPath is the path of the URL without its query, so requests to one page with many queries are one page.
	// Unlike the others it is always set on a request, because rules group requests by it.
	URLPath = "url_path"
	// ReferrerDecoded and ReferrerCompact are the same for the Referer header, where an attack can also be put.
	ReferrerDecoded = "referrer_decoded"
	ReferrerCompact = "referrer_compact"
	// TenMinutes is the ten-minute window of an event of an application or a web server, like
	// "2026-11-26T14:30Z". Rules count distinct windows to tell attempts spread over an hour from one burst.
	TenMinutes = "ten_minutes"
)

// addWindow adds the ten-minute window to an event of an application or a web server that has a time.
func addWindow(current event.Event) {
	if current.Time.IsZero() || current.Fields[event.Category] != "webserver" && current.Fields[event.Product] != "app" {
		return
	}
	current.Fields[TenMinutes] = current.Time.UTC().Truncate(10 * time.Minute).Format("2006-01-02T15:04Z")
}

// maxDecodes is how often a value is percent-decoded. Double encoding (%2527 for a quote) is a common way around
// a filter that decodes once; three rounds read it and stay cheap.
const maxDecodes = 3

var (
	sqlComment = regexp.MustCompile(`/\*.*?\*/`)
	spaces     = regexp.MustCompile(`\s+`)
)

// addDecoded adds the derived fields to a web request. Values are cut like every other value.
func addDecoded(fields map[string]string) {
	if fields[event.Category] != "webserver" {
		return
	}
	if url := fields[event.URL]; url != "" {
		path, _, _ := strings.Cut(url, "?")
		fields[URLPath] = limit(path, maxValueRunes)
		derive(fields, url, URLDecoded, URLCompact)
	}
	if referrer := fields[event.Referrer]; referrer != "" && referrer != "-" {
		derive(fields, referrer, ReferrerDecoded, ReferrerCompact)
	}
}

func derive(fields map[string]string, raw, decodedName, compactName string) {
	plain := percentDecodeAll(raw)
	decoded := sqlComment.ReplaceAllString(plain, " ")
	if decoded != raw {
		fields[decodedName] = limit(decoded, maxValueRunes)
	}
	compact := spaces.ReplaceAllString(sqlComment.ReplaceAllString(plain, ""), "")
	if compact != raw && compact != decoded {
		fields[compactName] = limit(compact, maxValueRunes)
	}
}

// percentDecodeAll decodes up to maxDecodes rounds, and keeps the result valid UTF-8 (%ff alone is no text).
func percentDecodeAll(raw string) string {
	decoded := raw
	for range maxDecodes {
		next := percentDecode(decoded)
		if next == decoded {
			break
		}
		decoded = next
	}

	return strings.ToValidUTF8(decoded, "?")
}

// percentDecode decodes one round: each valid %XX and each "+". A "%" that does not start a valid escape stays as
// it is, so a broken escape cannot hide the rest of the value (url.QueryUnescape gives up on the whole value).
// A decoded control character or NUL becomes a space, so a value can never hold one after decoding.
func percentDecode(raw string) string {
	if !strings.ContainsAny(raw, "%+") {
		return raw
	}
	var out strings.Builder
	out.Grow(len(raw))
	for index := 0; index < len(raw); index++ {
		switch character := raw[index]; {
		case character == '+':
			out.WriteByte(' ')
		case character == '%' && index+2 < len(raw) && isHex(raw[index+1]) && isHex(raw[index+2]):
			value := unhex(raw[index+1])<<4 | unhex(raw[index+2])
			if value < 0x20 || value == 0x7f {
				value = ' '
			}
			out.WriteByte(value)
			index += 2
		default:
			out.WriteByte(character)
		}
	}

	return out.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}

	return c - 'A' + 10
}
