package filerules

import (
	"embed"
	"io/fs"
)

//go:embed builtin/*.yml
var builtinFiles embed.FS

// Builtin gives the file rules that come with Omamori.
func Builtin() (Set, error) {
	system, err := fs.Sub(builtinFiles, "builtin")
	if err != nil {
		return Set{}, err
	}

	return LoadFS(system)
}
