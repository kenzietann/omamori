package gateway

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxLineLength = 200

func (gateway *Gateway) resolve(path string) (string, error) {
	resolved, err := gateway.root.Resolve(path)
	if err != nil {
		return "", ErrPathNotAllowed
	}

	return resolved, nil
}

func countLines(text string) int {
	if text == "" {
		return 0
	}

	lines := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		lines++
	}

	return lines
}

func shorten(line string) string {
	runes := []rune(line)
	if len(runes) <= maxLineLength {
		return line
	}

	return string(runes[:maxLineLength]) + "..."
}

func (gateway *Gateway) readTextFile(resolvedPath string) (string, error) {
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", ErrToolFailed
	}
	if !info.Mode().IsRegular() {
		return "", ErrInvalidArguments
	}

	file, err := os.Open(resolvedPath)
	if err != nil {
		return "", ErrToolFailed
	}
	defer file.Close()

	// Read one byte more than the limit, because the file may have grown since Stat.
	data, err := io.ReadAll(io.LimitReader(file, gateway.limits.MaxFileBytes+1))
	if err != nil {
		return "", ErrToolFailed
	}
	if int64(len(data)) > gateway.limits.MaxFileBytes {
		return "", ErrLimitExceeded
	}

	text := string(data)
	if countLines(text) > gateway.limits.MaxLines {
		return "", ErrLimitExceeded
	}

	return text, nil
}

// walkFiles lists the regular files under a path. Symlinks are skipped, never followed.
func (gateway *Gateway) walkFiles(ctx context.Context, resolvedPath string) (files []string, isFile, truncated bool, err error) {
	info, err := os.Lstat(resolvedPath)
	if err != nil {
		return nil, false, false, ErrToolFailed
	}
	if info.Mode().IsRegular() {
		return []string{resolvedPath}, true, false, nil
	}
	if !info.IsDir() {
		return nil, false, false, ErrInvalidArguments
	}

	err = filepath.WalkDir(resolvedPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ErrCancelled
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if len(files) >= gateway.limits.MaxFiles {
			truncated = true
			return fs.SkipAll
		}

		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, false, false, ErrCancelled
	}

	return files, false, truncated, nil
}

func readFile(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error) {
	resolved, err := gateway.resolve(arguments["path"])
	if err != nil {
		return Result{}, err
	}

	text, err := gateway.readTextFile(resolved)
	if err != nil {
		return Result{}, err
	}

	return Result{Text: text}, nil
}

func listDir(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error) {
	resolved, err := gateway.resolve(arguments["path"])
	if err != nil {
		return Result{}, err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return Result{}, ErrToolFailed
	}
	if !info.IsDir() {
		return Result{}, ErrInvalidArguments
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		return Result{}, ErrToolFailed
	}

	var names []string
	truncated := false

	for _, entry := range entries {
		if len(names) >= gateway.limits.MaxResults {
			truncated = true
			break
		}

		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}

	return Result{Text: strings.Join(names, "\n"), Truncated: truncated}, nil
}

func searchText(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error) {
	resolved, err := gateway.resolve(arguments["path"])
	if err != nil {
		return Result{}, err
	}

	files, isFile, truncated, err := gateway.walkFiles(ctx, resolved)
	if err != nil {
		return Result{}, err
	}

	var lines []string
	skipped := 0

search:
	for _, filePath := range files {
		if ctx.Err() != nil {
			return Result{}, ErrCancelled
		}

		text, err := gateway.readTextFile(filePath)
		if err != nil {
			if isFile {
				return Result{}, err
			}
			skipped++
			continue
		}

		for index, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, arguments["query"]) {
				continue
			}
			if len(lines) >= gateway.limits.MaxResults {
				truncated = true
				break search
			}

			lines = append(lines, fmt.Sprintf("%s:%d: %s", gateway.root.Relative(filePath), index+1, shorten(line)))
		}
	}

	return Result{Text: strings.Join(lines, "\n"), Truncated: truncated, Skipped: skipped}, nil
}

func runDetectors(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error) {
	resolved, err := gateway.resolve(arguments["path"])
	if err != nil {
		return Result{}, err
	}

	files, isFile, truncated, err := gateway.walkFiles(ctx, resolved)
	if err != nil {
		return Result{}, err
	}

	var lines []string
	skipped := 0

scan:
	for _, filePath := range files {
		if ctx.Err() != nil {
			return Result{}, ErrCancelled
		}

		text, err := gateway.readTextFile(filePath)
		if err != nil {
			if isFile {
				return Result{}, err
			}
			skipped++
			continue
		}

		_, findings := gateway.sanitizer.Sanitize(text)
		if len(findings) == 0 {
			continue
		}

		// The file name can hold a secret too, so it goes through the sanitizer.
		safePath, _ := gateway.sanitizer.Sanitize(gateway.root.Relative(filePath))

		lineNumber := 1
		position := 0
		for _, finding := range findings {
			if len(lines) >= gateway.limits.MaxResults {
				truncated = true
				break scan
			}

			lineNumber += strings.Count(text[position:finding.Start], "\n")
			position = finding.Start
			lines = append(lines, fmt.Sprintf("%s:%d: %s", safePath, lineNumber, finding.Placeholder))
		}
	}

	return Result{Text: strings.Join(lines, "\n"), Truncated: truncated, Skipped: skipped}, nil
}
