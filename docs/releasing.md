# Releasing

How a version of Omamori reaches users: the tag, the archives, the install script and Homebrew.

## One-time setup for Homebrew

1. Create a public GitHub repository named exactly `homebrew-tap` under the same account. It may be empty.
2. Create a fine-grained personal access token that can write the contents of that one repository only.
3. In the Omamori repository, add it as the Actions secret `HOMEBREW_TAP_TOKEN`
   (Settings → Secrets and variables → Actions).

Without the secret the release still works; the workflow says it skipped the tap.

## For each version

1. Add a `## [x.y.z] - date` section to `CHANGELOG.md` and update the version in `README.md`.
2. Commit, push to `main`, and wait for CI to pass.
3. Tag and push: `git tag -a vX.Y.Z -m "Omamori vX.Y.Z" && git push origin vX.Y.Z`.

The `release` workflow then runs the tests, builds the four archives and `checksums.txt`
([`scripts/release.sh`](../scripts/release.sh)), publishes the GitHub release, and writes
`Formula/omamori.rb` into the tap ([`scripts/formula.sh`](../scripts/formula.sh)). The formula takes its
sha256 values from the same `checksums.txt` that is uploaded, so they cannot differ.

## What users run

| Way | Command | Where it comes from |
|---|---|---|
| Homebrew | `brew install kenzietann/tap/omamori` | the tap formula |
| Script | `curl -fsSL https://raw.githubusercontent.com/kenzietann/omamori/main/install.sh \| sh` | the release archive, sha256 checked |
| Go | `go install github.com/kenzietann/omamori/cmd/omamori@latest` | the Go module proxy, built from the tag |

The Go way needs a public repository and the module path `github.com/kenzietann/omamori`. The packages are
under `internal/`, so Omamori can be installed this way but not imported as a library.

## Not done yet

- npm / `npx`: needs a wrapper package that brings the binary. Two ways: one package per system (no install script runs), or one package that downloads the archive after install.
- Homebrew core (plain `brew install omamori`): needs a well-known project; the tap comes first.
- Signing and notarizing the macOS binary.
