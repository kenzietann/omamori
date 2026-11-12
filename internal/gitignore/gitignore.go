// Package gitignore reads .gitignore rules and says whether a path is ignored. It follows the rules in
// the Git documentation (gitignore(5)): the last matching rule wins, a rule for a folder covers what is
// inside it, and a file cannot be taken back out of an ignored folder. It reads text only.
//
// It cannot know if a file was committed before it was ignored. A rule does not remove a file from git.
package gitignore

import (
	"regexp"
	"strings"
)

const (
	maxRules       = 5000
	maxPatternSize = 500
)

type rule struct {
	pattern  *regexp.Regexp
	negated  bool
	dirOnly  bool
	anchored bool
}

type Rules struct {
	rules []rule
}

// Parse reads the text of a .gitignore file. A line that cannot be used is skipped.
func Parse(text string) Rules {
	var parsed Rules
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if len(parsed.rules) >= maxRules {
			break
		}
		if current, ok := parseLine(line); ok {
			parsed.rules = append(parsed.rules, current)
		}
	}

	return parsed
}

func parseLine(line string) (rule, bool) {
	line = trimTrailingSpaces(line)
	if line == "" || strings.HasPrefix(line, "#") || len(line) > maxPatternSize {
		return rule{}, false
	}

	var current rule
	if strings.HasPrefix(line, "!") {
		current.negated = true
		line = line[1:]
	} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
		line = line[1:]
	}

	if strings.HasSuffix(line, "/") {
		current.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if line == "" {
		return rule{}, false
	}

	current.anchored = strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")

	compiled, err := regexp.Compile("^" + globToRegexp(line) + "$")
	if err != nil {
		return rule{}, false
	}
	current.pattern = compiled

	return current, true
}

func trimTrailingSpaces(line string) string {
	end := len(line)
	for end > 0 && line[end-1] == ' ' {
		if end >= 2 && line[end-2] == '\\' {
			break
		}
		end--
	}

	return line[:end]
}

// globToRegexp turns a glob into a regular expression for one path. "*" and "?" never cross a slash.
func globToRegexp(glob string) string {
	var out strings.Builder
	runes := []rune(glob)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		switch character {
		case '*':
			if index+1 < len(runes) && runes[index+1] == '*' {
				atStart := index == 0 || runes[index-1] == '/'
				for index+1 < len(runes) && runes[index+1] == '*' {
					index++
				}
				atEnd := index+1 == len(runes)
				slashAfter := index+1 < len(runes) && runes[index+1] == '/'
				switch {
				case atStart && slashAfter:
					out.WriteString("(?:.*/)?")
					index++
				case atStart && atEnd:
					out.WriteString(".*")
				default:
					out.WriteString("[^/]*")
				}
				continue
			}
			out.WriteString("[^/]*")
		case '?':
			out.WriteString("[^/]")
		case '[':
			end := closingBracket(runes, index)
			if end < 0 {
				out.WriteString(`\[`)
				continue
			}
			out.WriteString(classOf(runes[index+1 : end]))
			index = end
		case '\\':
			if index+1 < len(runes) {
				index++
				out.WriteString(regexp.QuoteMeta(string(runes[index])))
			}
		default:
			out.WriteString(regexp.QuoteMeta(string(character)))
		}
	}

	return out.String()
}

func closingBracket(runes []rune, open int) int {
	for index := open + 2; index < len(runes); index++ {
		if runes[index] == ']' {
			return index
		}
	}

	return -1
}

func classOf(inside []rune) string {
	var out strings.Builder
	out.WriteString("[")
	start := 0
	if len(inside) > 0 && (inside[0] == '!' || inside[0] == '^') {
		out.WriteString("^")
		start = 1
	}
	for _, character := range inside[start:] {
		if character == '\\' || character == '[' || character == ']' || character == '^' {
			out.WriteString(`\`)
		}
		out.WriteRune(character)
	}
	out.WriteString("]")

	return out.String()
}

func (parsed Rules) match(path string, isDir bool) (ignored, matched bool) {
	name := path[strings.LastIndex(path, "/")+1:]
	for index := len(parsed.rules) - 1; index >= 0; index-- {
		current := parsed.rules[index]
		if current.dirOnly && !isDir {
			continue
		}
		subject := name
		if current.anchored {
			subject = path
		}
		if current.pattern.MatchString(subject) {
			return !current.negated, true
		}
	}

	return false, false
}

type Layer struct {
	Dir   string
	Rules Rules
}

func Ignored(layers []Layer, path string) bool {
	path = strings.Trim(path, "/")
	if path == "" {
		return false
	}

	parts := strings.Split(path, "/")
	for count := 1; count <= len(parts); count++ {
		prefix := strings.Join(parts[:count], "/")
		isDir := count < len(parts)

		ignored := false
		for _, layer := range layers {
			relative, inside := within(layer.Dir, prefix)
			if !inside {
				continue
			}
			if decided, matched := layer.Rules.match(relative, isDir); matched {
				ignored = decided
			}
		}

		if count == len(parts) {
			return ignored
		}
		if ignored {
			return true
		}
	}

	return false
}

func within(dir, path string) (string, bool) {
	if dir == "" {
		return path, true
	}
	if strings.HasPrefix(path, dir+"/") {
		return path[len(dir)+1:], true
	}

	return "", false
}
