<div align="center">
  <img src="assets/packrai-og-banner.jpg" alt="PackrAI — npx packrai" width="800" />

  <h1>PackrAI</h1>

  <p><strong>Generate accurate, compliant SBOMs from any project — in one command.</strong></p>

  [![npm](https://img.shields.io/npm/v/packrai?color=00c851&logo=npm&logoColor=white)](https://www.npmjs.com/package/packrai)
  [![CI](https://github.com/RunTimeAdmin/PACKRAI/actions/workflows/ci.yml/badge.svg)](https://github.com/RunTimeAdmin/PACKRAI/actions/workflows/ci.yml)
  [![SBOM](https://github.com/RunTimeAdmin/PACKRAI/actions/workflows/sbom.yml/badge.svg)](https://github.com/RunTimeAdmin/PACKRAI/actions/workflows/sbom.yml)
  [![License: MIT](https://img.shields.io/badge/license-MIT-00c851)](LICENSE)
  [![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-blueviolet)](https://cyclonedx.org)
  [![SPDX 2.3](https://img.shields.io/badge/SPDX-2.3-blue)](https://spdx.dev)
</div>

```bash
npx packrai RunTimeAdmin/myapp@v2.1.0
```

Produces **CycloneDX 1.6** and **SPDX 2.3** in under 500ms. No Docker. No agents. No config files.

---

## Quick Start

```bash
# Scan a GitHub repo at a specific tag
npx packrai owner/repo@v1.2.0

# Scan the current directory
npx packrai .

# Scan a local directory
npx packrai ./my-project

# Private repo (uses $GITHUB_TOKEN automatically)
npx packrai owner/private-repo

# Diff two SBOMs — see what changed between releases
npx packrai diff old.cyclonedx.json new.cyclonedx.json

# Check for forbidden/restricted licenses
npx packrai . --license-check

# Skip vulnerability lookup (faster, offline-safe)
npx packrai owner/repo --no-vulns
```

Output files written to the current directory:
```
bom.cyclonedx.json   ← CycloneDX 1.6
bom.spdx.json        ← SPDX 2.3
```

---

## How It Works

```mermaid
flowchart LR
    subgraph sources["Lock Files (14 ecosystems)"]
        direction TB
        A["package-lock.json\nyarn.lock · pnpm-lock.yaml"]
        B["Cargo.lock\ngo.mod · poetry.lock"]
        C["pom.xml · Gemfile.lock\ncomposer.lock · packages.lock.json"]
    end

    subgraph engine["PackrAI Engine"]
        direction TB
        D[Detect] --> E[Parse dep graph]
        E --> F[Enrich: licenses\ndeps.dev API]
        E --> G[Enrich: vulns\nOSV batch API]
    end

    subgraph output["Output"]
        direction TB
        H[CycloneDX 1.6]
        I[SPDX 2.3]
        J[Quality score 0–100]
    end

    subgraph platform["Central Platform (optional)"]
        K[PackrAI API]
        L[(PostgreSQL)]
        M[Dashboard]
        K --> L --> M
    end

    sources --> engine
    F --> output
    G --> output
    output -->|ingest| platform
```

Lock files are the resolved dependency graph — authoritative, deterministic, and exact. PackrAI reads them directly instead of walking the filesystem, which is why it's 60–187× faster than Syft and Trivy on equivalent repos.

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
| **SBOM diff** | ✅ | ❌ | ❌ |
| **License policy** | ✅ | ❌ | ❌ |
| **VEX support** | ✅ | ❌ | ❌ |
| **Central repo** | ✅ | ❌ | ❌ |

### Benchmark Results

| Repo | Ecosystem | PackrAI | Syft | Trivy |
|------|-----------|---------|------|-------|
| `nestjs/nest` | npm | **463ms** | 27 731ms | 86 550ms |
| `psf/requests` | Python | **251ms** | 9 330ms | 10 502ms |
| `BurntSushi/ripgrep` | Rust | **268ms** | 11 823ms | 15 425ms |

Syft and Trivy run via Docker in this benchmark, adding ~3–5s of startup overhead. Native installs would be somewhat faster — but still an order of magnitude slower on lock-file repos. Reproduce with `npm run bench`.

---

## Features

### SBOM Generation
Produces fully-spec-compliant CycloneDX 1.6 and SPDX 2.3 with all CISA 2025 minimum elements: component name, version, supplier, purl, cryptographic hashes, license identifiers, dependency relationships, author, timestamp, and tool metadata.

### Vulnerability Enrichment
Every component is checked against the [OSV database](https://osv.dev) in a single batch call. Severity, CVSS score, and fix version are included in the SBOM output.

### License Compliance
```bash
npx packrai . --license-check
```
Categorises each component's license as **permissive**, **notice**, **restricted** (weak copyleft — review required), or **forbidden** (strong copyleft). Exits `1` if any forbidden license is found. Produces a license compliance score 0–100.

### SBOM Diffing
```bash
npx packrai diff v1.0.0.cyclonedx.json v1.1.0.cyclonedx.json
```
Shows exactly what changed between two releases: components added/removed/updated, and new or resolved vulnerabilities. Exits `1` if new vulnerabilities were introduced. Available both as a CLI command and via the API (`GET /api/v1/apps/:name/diff`).

### VEX Support
Mark vulnerabilities as `not_affected`, `fixed`, `affected`, or `under_investigation` via the API. `not_affected` statements suppress vulns from risk reports, keeping dashboards signal-rich.

### Quality Score
Every SBOM gets a completeness score (0–100) measuring alignment with CISA 2025 minimum elements: purl coverage, hash coverage, license coverage, and lock-file fidelity.

---

## GitHub Action

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
        uses: RunTimeAdmin/PACKRAI@v1
        with:
          format: both
          fail-on-critical: true
          upload-artifact: true
```

On every pull request, PackrAI will:
- Generate CycloneDX 1.6 + SPDX 2.3 SBOMs
- Post a summary comment to the PR with vulnerability count and quality score
- Upload SBOMs as artifacts with 90-day retention
- Block merge if critical vulnerabilities are found

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `format` | `both` | `both` · `cyclonedx` · `spdx` |
| `output-dir` | `sbom` | Directory to write SBOM files |
| `fail-on-critical` | `true` | Exit 1 if critical vulnerabilities found |
| `upload-artifact` | `true` | Upload SBOMs as GitHub Actions artifacts |
| `skip-vulns` | `false` | Skip OSV enrichment (faster, offline-safe) |
| `api-url` | `""` | PackrAI central API endpoint |
| `api-key` | `""` | PackrAI API key (`secrets.PACKRAI_API_KEY`) |
| `directory` | `.` | Directory to scan |

### Action Outputs

| Output | Description |
|--------|-------------|
| `cyclonedx-path` | Path to generated CycloneDX 1.6 BOM |
| `spdx-path` | Path to generated SPDX 2.3 BOM |
| `component-count` | Total components enumerated |
| `vulnerability-count` | Total known vulnerabilities |
| `critical-count` | Critical severity vulnerabilities (CVSS ≥ 9.0) |
| `quality-score` | SBOM completeness score 0–100 |

### With Central Tracking

```yaml
      - name: PackrAI
        uses: RunTimeAdmin/PACKRAI@v1
        with:
          format: both
          fail-on-critical: true
          upload-artifact: true
          api-url: ${{ vars.PACKRAI_API_URL }}
          api-key: ${{ secrets.PACKRAI_API_KEY }}
```

When `api-url` and `api-key` are set, SBOMs are automatically pushed to your PackrAI central instance for org-wide tracking. Upload failures do not fail the build.

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
| **Java** | `gradle.lockfile` | ✅ Full graph | Requires `--write-locks` |
| **.NET** | `packages.lock.json` | ✅ Full graph | SHA-512 hashes |
| **Ruby** | `Gemfile.lock` | ✅ Full graph | SHA-1 checksums via Bundler |
| **PHP** | `composer.lock` | ✅ Full graph | Licenses from package metadata |
| **Swift** | `Package.resolved` | ⚠️ Direct only | Git SHA hashes |
| **Dart/Flutter** | `pubspec.lock` | ⚠️ Direct only | SHA-256 hashes |

Monorepos are supported — PackrAI recurses up to 4 directories deep and deduplicates lock files per directory.

---

## CLI Reference

```
packrai <source> [options]
packrai diff <from> <to> [options]

Arguments:
  source                Local path, owner/repo[@ref], or https://github.com/... URL

Scan options:
  -o, --out <dir>       Output directory (default: current directory)
  -n, --name <name>     Project name override
  -v, --ver <version>   Version override
  -a, --author <org>    Author or organisation name
  --token <token>       GitHub token for private repos (or set $GITHUB_TOKEN)
  --format <fmt>        both | cyclonedx | spdx  (default: both)
  --license-check       Flag forbidden/restricted licenses; exit 1 if any found
  --no-vulns            Skip OSV vulnerability enrichment
  --no-licenses         Skip deps.dev license enrichment
  --no-recursive        Do not recurse into subdirectories
  --json                Print summary as JSON (machine-readable, for CI)

Diff options:
  --json                Machine-readable JSON diff output
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Critical vulnerabilities found, or forbidden license detected (`--license-check`) |
| `2` | Fatal error — no lock files, clone failed, or unrecoverable parse error |

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
  ],
  "vulnerabilities": [
    {
      "id": "GHSA-rv95-896h-c2vc",
      "ratings": [{ "score": 7.5, "severity": "high", "method": "CVSSv3" }],
      "affects": [{ "ref": "pkg:npm/express@4.18.2" }]
    }
  ]
}
```

### SPDX 2.3
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [...],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-express-4.18.2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-accepts-1.3.8"
    }
  ]
}
```

Both formats include all CISA 2025 minimum elements, full transitive dependency relationships, cryptographic hashes, SPDX license identifiers, and OSV vulnerability data.

---

## Central Platform (Self-Hosted)

The PackrAI API server answers org-wide questions like:

> "Which of our apps are exposed to CVE-2021-44228, and do any of them have a fix available?"

```mermaid
flowchart TD
    subgraph ci["CI/CD (GitHub Actions)"]
        A[PackrAI Action] -->|POST /ingest| B
    end

    subgraph api["PackrAI API"]
        B[Ingest endpoint]
        C[Search endpoint]
        D[Report endpoint]
        E[VEX endpoint]
        F[Diff endpoint]
    end

    subgraph db["PostgreSQL"]
        G[(organizations)]
        H[(sboms)]
        I[(components)]
        J[(vulnerabilities)]
        K[(vex_statements)]
        L[(app_latest_sboms)]
    end

    B --> G & H & I & J & L
    C --> I & J & K
    D --> L & J & K
    E --> K
    F --> H
```

### Start the API

```bash
# With Docker (recommended)
cp .env.example .env      # set HMAC_SECRET and POSTGRES_PASSWORD
docker compose up -d
```

API available at `http://localhost:3080`.

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/ingest` | Ingest a new SBOM (called by the Action) |
| `GET` | `/api/v1/apps` | List all apps with risk summary |
| `GET` | `/api/v1/apps/:name/diff` | Diff latest two SBOMs for an app |
| `GET` | `/api/v1/search?cve=CVE-...` | Which apps are exposed to this CVE? |
| `GET` | `/api/v1/report` | Org-wide risk report |
| `POST` | `/api/v1/vex` | Add a VEX statement |
| `GET` | `/api/v1/vex` | List VEX statements |
| `POST` | `/api/v1/keys` | Issue a scoped API key |

See [`src/api/schema.sql`](src/api/schema.sql) for the full database schema.

---

## Development

```bash
git clone https://github.com/RunTimeAdmin/PACKRAI
cd PACKRAI
npm install

npm test          # unit tests (66 tests, no external deps)
npm run e2e       # integration tests (requires docker compose up -d)
npm run bench     # benchmark vs Syft and Trivy
node bin/packrai.js . --no-vulns   # run the CLI locally
```

### Project Structure

```
packrai/
├── bin/packrai.js          CLI entry point (scan + diff subcommands)
├── src/
│   ├── pipeline.js         Orchestration: detect → parse → enrich → generate
│   ├── diff.js             SBOM diffing: components and vulnerabilities
│   ├── licensePolicy.js    License tier classification and compliance scoring
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
│   │   ├── swift.js        Package.resolved
│   │   ├── dart.js         pubspec.lock
│   │   ├── detect.js       Lock file detection + deduplication
│   │   └── index.js        Parser dispatcher
│   ├── generators/
│   │   ├── cyclonedx.js    CycloneDX 1.6 generator + validator
│   │   └── spdx.js         SPDX 2.3 generator
│   └── api/
│       ├── server.js       Express API server
│       ├── db.js           PostgreSQL connection pool + transaction helper
│       └── schema.sql      Database schema
├── deploy/
│   ├── migrate_001_app_latest_sboms.sql
│   ├── migrate_002_vex.sql
│   └── docker-compose.yml  API + Postgres production stack
├── tests/
│   ├── parsers.test.js     Parser unit tests
│   └── fixtures/           Sample lock files (all 14 ecosystems)
├── examples/
│   └── github-workflow.yml Annotated copy-paste workflow
└── action.yml              GitHub Action definition
```

### Adding a New Ecosystem

1. Write `src/parsers/<ecosystem>.js` — export a `parse*` function returning `Component[]`
2. Add detection entry in `src/parsers/detect.js` (`LOCK_FILE_BY_NAME`)
3. Add dispatcher case in `src/parsers/index.js`
4. Add `case '<ecosystem>'` in `src/component.js` `makePurl()`
5. Add fixture in `tests/fixtures/` and tests in `tests/parsers.test.js`

---

## Standards Compliance

| Standard | Version | Status |
|----------|---------|--------|
| [CycloneDX](https://cyclonedx.org/specification/overview/) | 1.6 | ✅ Full |
| [SPDX](https://spdx.dev/specifications/) | 2.3 | ✅ Full |
| [NTIA Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) | 2021 | ✅ All 7 fields |
| [CISA Minimum Elements](https://www.cisa.gov/resources-tools/resources/software-bill-materials-sbom) | 2025 | ✅ purl, hashes, licenses, relationships, metadata |
| [EO 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/) | — | ✅ Supply chain security |
| [OpenVEX / CycloneDX VEX](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex_508c.pdf) | — | ✅ Via API |

---

## Known Limitations

PackrAI is a **lock-file-first** SBOM generator. This makes it fast and deterministic, but it does not replace container or filesystem scanners for all use cases.

| Area | Detail |
|------|--------|
| **Container/image scanning** | Does not scan Docker image layers or OS packages. Combine with Trivy for container SBOMs. |
| **Compiled binaries** | SBOMs are generated from lock files, not compiled output or vendored binaries. |
| **No lock file → no SBOM** | `requirements.txt` produces direct-only output with a warning. Projects without any committed lock file are not supported. |
| **Java (Maven)** | Transitive resolution requires `mvn` to be installed locally. Without it, direct deps only. |
| **Swift / Dart** | Flat resolved set only — no dependency graph available in the lock file format. |
| **Gradle** | Requires `--write-locks` to produce `gradle.lockfile`. |
| **.NET** | Requires `RestorePackagesWithLockFile=true` and a committed `packages.lock.json`. |

---

## License

MIT — see [LICENSE](LICENSE)
