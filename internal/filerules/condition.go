package filerules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The condition of a file rule is a small language in the way of YARA:
//
//	a and (b or not c)
//	any of them          all of them          2 of them
//	any of (a, b)        2 of (a, b, c)       any of shell_*
type node interface {
	eval(found func(string) bool) bool
}

type (
	andNode  struct{ left, right node }
	orNode   struct{ left, right node }
	notNode  struct{ inner node }
	nameNode struct{ name string }
	// ofNode is true when at least need of the names are found. need is len(names) for "all of".
	ofNode struct {
		need  int
		names []string
	}
)

func (n andNode) eval(found func(string) bool) bool  { return n.left.eval(found) && n.right.eval(found) }
func (n orNode) eval(found func(string) bool) bool   { return n.left.eval(found) || n.right.eval(found) }
func (n notNode) eval(found func(string) bool) bool  { return !n.inner.eval(found) }
func (n nameNode) eval(found func(string) bool) bool { return found(n.name) }
func (n ofNode) eval(found func(string) bool) bool {
	count := 0
	for index, name := range n.names {
		if found(name) {
			count++
		}
		if count >= n.need {
			return true
		}
		if count+len(n.names)-index-1 < n.need {
			return false
		}
	}

	return false
}

var reserved = map[string]bool{"and": true, "or": true, "not": true, "of": true, "any": true, "all": true, "them": true}

const maxDepth = 32

type parser struct {
	tokens   []string
	position int
	names    []string
	depth    int
}

func parseCondition(text string, names []string) (node, error) {
	if len(text) > maxCondition {
		return nil, errors.New("the condition is too long")
	}
	parsed := &parser{tokens: tokenize(text), names: names}
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
		switch character {
		case '(', ')', ',':
			flush()
			tokens = append(tokens, string(character))
		case ' ', '\t', '\n', '\r':
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

func (parsed *parser) next() string {
	token := parsed.peek()
	if parsed.position < len(parsed.tokens) {
		parsed.position++
	}

	return token
}

func (parsed *parser) enter() error {
	if parsed.depth++; parsed.depth > maxDepth {
		return errors.New("the condition is nested too deep")
	}

	return nil
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
	if parsed.peek() != "not" {
		return parsed.primary()
	}
	parsed.position++
	if err := parsed.enter(); err != nil {
		return nil, err
	}
	defer func() { parsed.depth-- }()
	inner, err := parsed.not()
	if err != nil {
		return nil, err
	}

	return notNode{inner}, nil
}

func (parsed *parser) primary() (node, error) {
	token := parsed.peek()
	switch {
	case token == "":
		return nil, errors.New("the condition ends too early")
	case token == "(":
		parsed.position++
		if err := parsed.enter(); err != nil {
			return nil, err
		}
		defer func() { parsed.depth-- }()
		inner, err := parsed.or()
		if err != nil {
			return nil, err
		}
		if parsed.next() != ")" {
			return nil, errors.New("a ( has no )")
		}

		return inner, nil
	case token == "any" || token == "all" || isNumber(token):
		return parsed.of()
	case reserved[token] || token == ")" || token == ",":
		return nil, fmt.Errorf("%q is not in its place", token)
	}
	parsed.position++
	if !parsed.known(token) {
		return nil, fmt.Errorf("the condition names %q, which is not a string of the rule", truncate(token, 40))
	}

	return nameNode{token}, nil
}

func (parsed *parser) of() (node, error) {
	quantity := parsed.next()
	if parsed.next() != "of" {
		return nil, fmt.Errorf("%q must be followed by of", quantity)
	}
	var names []string
	switch target := parsed.next(); {
	case target == "them":
		names = parsed.names
	case target == "(":
		for {
			name := parsed.next()
			if !parsed.known(name) {
				return nil, fmt.Errorf("the list names %q, which is not a string of the rule", truncate(name, 40))
			}
			names = append(names, name)
			if separator := parsed.next(); separator == ")" {
				break
			} else if separator != "," {
				return nil, errors.New("a list must be like (a, b, c)")
			}
		}
	case strings.HasSuffix(target, "*") && !strings.Contains(strings.TrimSuffix(target, "*"), "*"):
		prefix := strings.TrimSuffix(target, "*")
		for _, name := range parsed.names {
			if strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("no string of the rule starts with %q", truncate(prefix, 40))
		}
	default:
		return nil, errors.New("of must be followed by them, a list like (a, b) or a name with * at its end")
	}

	need := 1
	switch {
	case quantity == "all":
		need = len(names)
	case quantity != "any":
		need, _ = strconv.Atoi(quantity)
		if need < 1 || need > len(names) {
			return nil, fmt.Errorf("%d of a list of %d can never be true", need, len(names))
		}
	}

	return ofNode{need: need, names: names}, nil
}

func (parsed *parser) known(name string) bool {
	for _, current := range parsed.names {
		if current == name {
			return true
		}
	}

	return false
}

func isNumber(token string) bool {
	if token == "" || len(token) > 3 {
		return false
	}
	for _, character := range token {
		if character < '0' || character > '9' {
			return false
		}
	}

	return true
}
