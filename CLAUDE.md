# Claude Code Guidelines for `bomhound`

> **Authoritative Ecosystem Runbook:** [`spanreed/docs/knowledge-base/10-bomhound.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/10-bomhound.md)

## Build & Test Commands
- **Build Binary:** `go build -o bin/bomhound ./cmd/bomhound`
- **Unit Tests:** `go test -v ./...`
- **Linter:** `golangci-lint run`
- **Enrich SBOM:** `./bin/bomhound enrich --input <input.json> --output <output.json>`
- **Resolve Vanity Domain:** `./bin/bomhound resolve --domain <pkg>`

## Code Style & Architectural Invariants
- Unabridged copyright notice preservation (Apache 2.0 §4c / 17 U.S.C. § 1202).
- Standard CycloneDX `Component.Evidence.Copyright` schema fidelity via `cyclonedx-go`.
- Go vanity domain resolution (`k8s.io/*`, `golang.org/x/*`, etc.) with 3-hop redirect limits.
- Content-addressed local caching in `~/.bomhound/cache/` to eliminate rate limits.
- Fail closed on malformed CycloneDX schemas.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
