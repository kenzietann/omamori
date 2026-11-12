package rules

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

type node interface {
	eval(results func(string) bool) bool
}

type (
	andNode  struct{ left, right node }
	orNode   struct{ left, right node }
	notNode  struct{ inner node }
	nameNode struct{ name string }
	ofNode   struct {
		all   bool
		names []string
	}
)

func (n andNode) eval(results func(string) bool) bool {
	return n.left.eval(results) && n.right.eval(results)
}
func (n orNode) eval(results func(string) bool) bool {
	return n.left.eval(results) || n.right.eval(results)
}
func (n notNode) eval(results func(string) bool) bool  { return !n.inner.eval(results) }
func (n nameNode) eval(results func(string) bool) bool { return results(n.name) }
func (n ofNode) eval(results func(string) bool) bool {
	for _, name := range n.names {
		if results(name) != n.all {
			return !n.all
		}
	}

	return n.all
}

const maxDepth = 32

type parser struct {
	tokens     []string
	position   int
	selections map[string]selection
	depth      int
}

func parseCondition(text string, selections map[string]selection) (node, error) {
	if len(text) > maxCondition {
		return nil, errors.New("the condition is too long")
	}

	parsed := &parser{tokens: tokenize(text), selections: selections}
	result, err := parsed.or()
	if err != nil {
		return nil, err
	}
	if parsed.position != len(parsed.tokens) {
		return nil, errors.New("the condition has something extra at its end")
	}

	return result, nil
}

func tokenize(text string) []string {
	var tokens []string
	var word strings.Builder
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for _, character := range text {
		switch {
		case character == '(' || character == ')':
			flush()
			tokens = append(tokens, string(character))
		case character == ' ' || character == '\t' || character == '\n' || character == '\r':
			flush()
		default:
			word.WriteRune(character)
		}
	}
	flush()

	return tokens
}

func (parsed *parser) peek() string {
	if parsed.position < len(parsed.tokens) {
		return strings.ToLower(parsed.tokens[parsed.position])
	}

	return ""
}

func (parsed *parser) or() (node, error) {
	left, err := parsed.and()
	if err != nil {
		return nil, err
	}
	for parsed.peek() == "or" {
		parsed.position++
		right, err := parsed.and()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}

	return left, nil
}

func (parsed *parser) and() (node, error) {
	left, err := parsed.not()
	if err != nil {
		return nil, err
	}
	for parsed.peek() == "and" {
		parsed.position++
		right, err := parsed.not()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}

	return left, nil
}

func (parsed *parser) not() (node, error) {
	if parsed.peek() == "not" {
		parsed.position++
		parsed.depth++
		defer func() { parsed.depth-- }()
		if parsed.depth > maxDepth {
			return nil, errors.New("the condition is nested too deep")
		}
		inner, err := parsed.not()
		if err != nil {
			return nil, err
		}

		return notNode{inner}, nil
	}

	return parsed.primary()
}

func (parsed *parser) primary() (node, error) {
	if parsed.position >= len(parsed.tokens) {
		return nil, errors.New("the condition ends too early")
	}
	token := parsed.tokens[parsed.position]
	switch {
	case token == "(":
		parsed.position++
		parsed.depth++
		defer func() { parsed.depth-- }()
		if parsed.depth > maxDepth {
			return nil, errors.New("the condition is nested too deep")
		}
		inner, err := parsed.or()
		if err != nil {
			return nil, err
		}
		if parsed.peek() != ")" {
			return nil, errors.New("a bracket is not closed")
		}
		parsed.position++

		return inner, nil
	case strings.ToLower(token) == "all" || token == "1":
		return parsed.of()
	case token == ")" || isKeyword(token):
		return nil, fmt.Errorf("the condition has %q in a wrong place", truncate(token, 20))
	}

	parsed.position++
	if _, known := parsed.selections[token]; !known {
		return nil, fmt.Errorf("the condition names %q, which is not a selection", truncate(token, 40))
	}

	return nameNode{token}, nil
}

func (parsed *parser) of() (node, error) {
	all := strings.ToLower(parsed.tokens[parsed.position]) == "all"
	parsed.position++
	if parsed.peek() != "of" || parsed.position+1 >= len(parsed.tokens) {
		return nil, errors.New("\"of\" is missing, or there is no name after it")
	}
	pattern := parsed.tokens[parsed.position+1]
	parsed.position += 2

	var names []string
	for name := range parsed.selections {
		if matched, _ := path.Match(pattern, name); matched || strings.ToLower(pattern) == "them" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no selection fits %q", truncate(pattern, 40))
	}
	sort.Strings(names)

	return ofNode{all: all, names: names}, nil
}

func isKeyword(token string) bool {
	switch strings.ToLower(token) {
	case "and", "or", "not", "of":
		return true
	}

	return false
}
