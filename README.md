# PackrAI

Generate accurate, compliant SBOMs from any GitHub repo or local project — in one command.

```bash
npx packrai RunTimeAdmin/myapp@v2.1.0
```

Produces **CycloneDX 1.6** and **SPDX 2.3** in under 5 seconds. No Docker. No agents. No config files.

---

## Quick Start

```bash
# Scan a GitHub repo at a specific tag
npx packrai owner/repo@v1.2.0

# Scan the default branch
npx packrai owner/repo

# Scan a local directory
npx packrai ./my-project

# Private repo (uses $GITHUB_TOKEN automatically)
npx packrai owner/private-repo

# Skip vulnerability lookup (faster, offline-safe)
npx packrai owner/repo --no-vulns
```

Output files written to the current directory:
```
bom.cyclonedx.json   ← CycloneDX 1.6
bom.spdx.json        ← SPDX 2.3
```

---

## Why PackrAI

| | PackrAI | Syft | Trivy |
|---|---|---|---|
| **Speed** | **250–465ms** | 9–28s | 10–87s |
| **Approach** | Lock-file parsing | Filesystem scan | Filesystem + image scan |
| **Transitives** | Full graph | Partial | Partial |
| **Dep graph** | ✅ | ✅ | ❌ |
| **Zero config** | ✅ | ❌ | ❌ |
| **GitHub URL** | ✅ | ❌ | ❌ |
| **Central repo** | ✅ (self-hosted) | ❌ | ❌ |

**Why lock files beat filesystem scanning:**
Lock files are the resolved dependency graph. They're authoritative, deterministic, and exact — no heuristics, no guessing, no double-counting. Syft and Trivy walk the filesystem and infer packages, which is slower and less accurate for transitive dependencies.

## Benchmark Results

PackrAI is sub-500ms across all three benchmark repos because it reads resolved lock files directly instead of walking the filesystem or performing broader image-style analysis. On `nestjs/nest`, it completed in 463ms versus 27.7s for Syft and 86.5s for Trivy — a 60× speedup over Syft and 187× over Trivy for this benchmark setup.

| Repo | Ecosystem | PackrAI | Syft | Trivy |
|------|-----------|---------|------|-------|
| `nestjs/nest` | npm | **463ms** | 27 731ms | 86 550ms |
| `psf/requests` | Python | **251ms** | 9 330ms | 10 502ms |
| `BurntSushi/ripgrep` | Rust | **268ms** | 11 823ms | 15 425ms |

Different tools solve different problems. Syft and Trivy inspect broader filesystem and container context — that work is genuinely more complex and their slower speed is not purely overhead. PackrAI is intentionally narrower: fast, deterministic SBOM generation from lock files.

Reproduce with:
```bash
docker pull anchore/syft && docker pull aquasec/trivy
npm run bench
```

---

## Supported Ecosystems

| Ecosystem | Lock File | Transitives | Notes |
|-----------|-----------|-------------|-------|
| **npm** | `package-lock.json` v1/v2/v3 | ✅ Full graph | Hoisting-aware resolver |
| **npm** | `pnpm-lock.yaml` v6/v9 | ✅ Full graph | Peer suffix handling |
| **npm** | `yarn.lock` v1 | ✅ Full graph | |
| **Python** | `poetry.lock` | ✅ Full graph | |
| **Python** | `Pipfile.lock` | ✅ Full graph | |
| **Python** | `requirements.txt` | ⚠️ Direct only | Warns on missing transitives |
| **Rust** | `Cargo.lock` | ✅ Full graph | SHA-256 checksums |
| **Go** | `go.mod` + `go.sum` | ✅ Full graph | Direct/indirect detection |
| **Java** | `pom.xml` | ✅ + `mvn` transitives | Resolves `${property}` vars |
| **Java** | `gradle.lockfile` | ✅ Full graph | Scope-aware; requires `--write-locks` |
| **.NET** | `packages.lock.json` | ✅ Full graph | SHA-512 hashes; requires `RestorePackagesWithLockFile` |
| **Ruby** | `Gemfile.lock` | ✅ Full graph | SHA-1 checksums via Bundler |
| **PHP** | `composer.lock` | ✅ Full graph | MIT/BSD licenses from package metadata |
| **Swift** | `Package.resolved` | ⚠️ Direct only | No dep graph in format; git SHA hashes |
| **Dart/Flutter** | `pubspec.lock` | ⚠️ Direct only | No dep graph in format; SHA-256 hashes |

Monorepos are supported — PackrAI recurses up to 4 directories deep and deduplicates lock files per directory.

---

## Output Formats

### CycloneDX 1.6
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [{ "license": { "id": "MIT" } }],
      "hashes": [{ "alg": "SHA-512", "content": "..." }],
      "scope": "required"
    }
  ],
  "dependencies": [
    { "ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/accepts@1.3.8"] }
  ]
}
```

### SPDX 2.3
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [...],
  "relationships": [
    { "spdxElementId": "SPDXRef-...", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-..." }
  ]
}
```

Both formats include:
- All CISA 2025 minimum elements
- Full transitive dependency relationships
- Cryptographic hashes (SHA-256 / SHA-512 from lock files)
- SPDX license identifiers (enriched via [deps.dev](https://deps.dev))
- OSV vulnerability data (enriched via [osv.dev](https://osv.dev))
- SBOM quality score (0–100)

---

## CLI Reference

```
packrai <source> [options]

Arguments:
  source                Local path, owner/repo[@ref], or https://github.com/... URL

Options:
  -o, --out <dir>       Output directory (default: current directory)
  -n, --name <name>     Project name override
  -v, --ver <version>   Version override
  -a, --author <org>    Author or organisation name
  --token <token>       GitHub token for private repos (or set $GITHUB_TOKEN)
  --format <fmt>        both | cyclonedx | spdx  (default: both)
  --no-vulns            Skip OSV vulnerability enrichment
  --no-licenses         Skip deps.dev license enrichment
  --no-recursive        Do not recurse into subdirectories
  --json                Print summary as JSON (machine-readable, for CI)
  -V, --version         Print version
  -h, --help            Show help
```

### Exit Codes
| Code | Meaning |
|------|---------|
| `0` | Success — no critical vulnerabilities |
| `1` | Critical vulnerabilities found (human output mode only; use `--json` for non-blocking CI output) |
| `2` | Fatal error — no lock files found, clone failed, or unrecoverable parse error |

> **Note:** The GitHub Action uses `--json` for generation (always exits 0), then enforces gating in a separate final step. This ensures artifacts are uploaded and PR comments are posted even when criticals are found.

---

## GitHub Actions

Drop this into `.github/workflows/sbom.yml`:

```yaml
name: SBOM

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: PackrAI
        uses: packrai/sbom-action@v1
        with:
          format: both
          fail-on-critical: true
          upload-artifact: true
```

On every pull request, PackrAI will:
- Generate CycloneDX + SPDX SBOMs
- Post a summary comment to the PR
- Upload SBOMs as artifacts (90-day retention)
- Block merge if critical vulnerabilities are found

See [`examples/github-workflow.yml`](examples/github-workflow.yml) for the full annotated example.

---

## Central Platform (Self-Hosted)

PackrAI includes an API server for org-wide SBOM management — the layer that answers:

> "Where across all our apps are we exposed to CVE-2021-44228?"

### Start the API

**With Docker (recommended):**
```bash
cp .env.example .env      # set ADMIN_KEY and POSTGRES_PASSWORD
docker compose up -d
```
API is available at `http://localhost:3080`. Postgres data is persisted in a named volume.

**Without Docker (requires Postgres):**
```bash
cp .env.example .env      # set DATABASE_URL and ADMIN_KEY
npm run serve
```

### Key Endpoints

```bash
# Ingest an SBOM (called by GitHub Action automatically)
POST /api/v1/ingest

# Search: which apps are exposed to a CVE?
GET  /api/v1/search?cve=CVE-2021-44228

# List all apps with risk summary
GET  /api/v1/apps

# Org-wide risk report
GET  /api/v1/report
```

See [`src/api/schema.sql`](src/api/schema.sql) for the full database schema.

---

## Development

```bash
# Clone and install
git clone https://github.com/RunTimeAdmin/PACKRAI
cd PACKRAI
npm install

# Unit tests (no external dependencies)
npm test

# End-to-end integration test (requires docker compose up -d first)
npm run e2e

# Benchmark PackrAI vs Syft vs Trivy
npm run bench

# Run the CLI locally
node bin/packrai.js owner/repo --no-vulns

# Start the API + Postgres
cp .env.example .env   # edit ADMIN_KEY and POSTGRES_PASSWORD
docker compose up -d
```

### Project Structure

```
packrai/
├── bin/packrai.js          CLI entry point
├── src/
│   ├── pipeline.js         Orchestration (detect → parse → enrich → generate)
│   ├── component.js        Shared component model + purl generation
│   ├── github.js           GitHub URL parsing + shallow clone
│   ├── osv.js              OSV vulnerability enrichment (batch API)
│   ├── licenses.js         License enrichment (deps.dev API)
│   ├── parsers/
│   │   ├── npm.js          package-lock.json v1/v2/v3, yarn.lock
│   │   ├── pnpm.js         pnpm-lock.yaml v6/v9
│   │   ├── python.js       poetry.lock, Pipfile.lock, requirements.txt
│   │   ├── cargo.js        Cargo.lock
│   │   ├── golang.js       go.mod + go.sum
│   │   ├── maven.js        pom.xml
│   │   ├── gradle.js       gradle.lockfile
│   │   ├── dotnet.js       packages.lock.json (NuGet)
│   │   ├── ruby.js         Gemfile.lock
│   │   ├── php.js          composer.lock
│   │   ├── detect.js       Lock file auto-detection + deduplication
│   │   └── index.js        Parser dispatcher
│   ├── generators/
│   │   ├── cyclonedx.js    CycloneDX 1.6 generator
│   │   └── spdx.js         SPDX 2.3 generator
│   └── api/
│       ├── server.js       Express API server
│       ├── db.js           PostgreSQL connection pool
│       └── schema.sql      Database schema
├── scripts/
│   └── benchmark.js        Benchmark PackrAI vs Syft vs Trivy
├── Dockerfile              Multi-stage API server image
├── docker-compose.yml      API + Postgres stack
├── tests/
│   ├── parsers.test.js     Parser unit tests (66 tests)
│   └── fixtures/           Sample lock files for testing
├── examples/
│   └── github-workflow.yml Copy-paste GitHub Actions workflow
└── action.yml              GitHub Action definition
```

### Adding a New Ecosystem

1. Write `src/parsers/<ecosystem>.js` — export a `parse*` function returning `Component[]`
2. Add detection entry in `src/parsers/detect.js` (`LOCK_FILE_PATTERNS`)
3. Add dispatcher case in `src/parsers/index.js`
4. Add `case '<ecosystem>'` in `src/component.js` `makePurl()`
5. Add fixture in `tests/fixtures/` and tests in `tests/parsers.test.js`

---

## Standards Compliance

- **CycloneDX 1.6** — OWASP BOM specification
- **SPDX 2.3** — Linux Foundation SPDX specification
- **NTIA Minimum Elements** — all 7 required fields present
- **CISA 2025 Minimum Elements** — purl, hashes, licenses, relationships, metadata
- **EO 14028** — US Executive Order on supply chain security

---

## Known Limitations

PackrAI is a **lock-file-first** SBOM generator. This makes it fast and accurate for dependency graphs, but it is not a universal replacement for filesystem scanners like Syft or Trivy.

### What it does not cover

| Area | Detail |
|------|--------|
| **Container/image scanning** | PackrAI does not scan Docker image layers or OS-level packages. For container SBOMs, combine with Trivy. |
| **Compiled binaries** | SBOMs are generated from source lock files, not from inspecting compiled output or vendored binaries. |
| **Dynamically loaded plugins** | Runtime-only or lazily loaded dependencies not reflected in lock files will not appear. |
| **No lock file → no SBOM** | If a project does not commit a lock file (some library maintainers intentionally do not), PackrAI cannot generate a transitive SBOM. `requirements.txt` produces direct-only output with a warning. |

### Per-ecosystem limitations

| Ecosystem | Limitation |
|-----------|-----------|
| **Java (Maven)** | Transitive resolution requires `mvn` to be installed locally. Without it, PackrAI returns direct dependencies only and prints a warning. |
| **Swift / Dart** | `Package.resolved` and `pubspec.lock` do not encode the full dependency graph — only the flat resolved set. `is_direct` detection is not available for these ecosystems. |
| **Gradle** | Requires `--write-locks` to have been run in the project to produce `gradle.lockfile`. Projects without lock files are skipped. |
| **.NET** | Requires `RestorePackagesWithLockFile=true` in the project. `packages.lock.json` must be committed. |

### Benchmark context

The speed comparison reflects a specific scenario: shallow-cloned repos with committed lock files. Syft and Trivy run via Docker in this setup, which adds ~3–5s of container startup overhead. Native installs would be somewhat faster — but still an order of magnitude slower for lock-file repos. See the Benchmark Results section for the full caveat.

---

## License

MIT — see [LICENSE](LICENSE)
