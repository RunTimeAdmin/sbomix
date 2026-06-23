'use strict';

/**
 * Lock file detection.
 * Walks a directory (non-recursively by default, recursive for monorepos)
 * and returns all parseable lock files with their type and path.
 */

const fs = require('fs');
const path = require('path');

const LOCK_FILE_PATTERNS = [
    { file: 'package-lock.json', type: 'npm-lock',    ecosystem: 'npm'    },
    { file: 'yarn.lock',         type: 'yarn-lock',   ecosystem: 'npm'    },
    { file: 'pnpm-lock.yaml',    type: 'pnpm-lock',   ecosystem: 'npm'    },
    { file: 'poetry.lock',       type: 'poetry-lock', ecosystem: 'pypi'   },
    { file: 'Pipfile.lock',      type: 'pipfile-lock',ecosystem: 'pypi'   },
    { file: 'requirements.txt',  type: 'requirements',ecosystem: 'pypi'   },
    { file: 'Cargo.lock',        type: 'cargo-lock',  ecosystem: 'cargo'  },
    { file: 'go.mod',            type: 'go-modules',  ecosystem: 'golang' },
    { file: 'pom.xml',           type: 'maven-pom',   ecosystem: 'maven'  },
    { file: 'gradle.lockfile',   type: 'gradle-lock', ecosystem: 'maven'  },
    { file: 'packages.lock.json',type: 'nuget-lock',    ecosystem: 'nuget'    },
    { file: 'Gemfile.lock',       type: 'gemfile-lock',  ecosystem: 'gem'      },
    { file: 'composer.lock',      type: 'composer-lock', ecosystem: 'composer' },
    { file: 'Package.resolved',   type: 'swift-lock',    ecosystem: 'swift'    },
    { file: 'pubspec.lock',       type: 'pubspec-lock',  ecosystem: 'pub'      },
];

// O(1) lookup map built once at module load — avoids linear scan per directory entry
const LOCK_FILE_BY_NAME = new Map(LOCK_FILE_PATTERNS.map((p) => [p.file, p]));

// Directories to skip when walking
const SKIP_DIRS = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build', 'target',
    '.venv', 'venv', '__pycache__', '.tox',
]);

/**
 * Find all lock files under `rootDir`.
 * @param {string} rootDir
 * @param {{ recursive?: boolean, maxDepth?: number }} [opts]
 * @returns {Array<{ type, ecosystem, path }>}
 */
function detect(rootDir, opts = {}) {
    const { recursive = true, maxDepth = 4 } = opts;
    const found = [];
    walk(rootDir, found, 0, maxDepth, recursive);

    // Prefer richer lock files over weaker ones in the same directory
    return deduplicate(found);
}

function walk(dir, found, depth, maxDepth, recursive) {
    if (depth > maxDepth) return;

    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return;
    }

    for (const entry of entries) {
        if (entry.isDirectory()) {
            if (recursive && !SKIP_DIRS.has(entry.name)) {
                walk(path.join(dir, entry.name), found, depth + 1, maxDepth, recursive);
            }
            continue;
        }

        const pattern = LOCK_FILE_BY_NAME.get(entry.name);
        if (pattern) {
            found.push({ ...pattern, path: path.join(dir, entry.name) });
        }
    }
}

// If a directory has both package-lock.json and yarn.lock, prefer package-lock.
// If it has both requirements.txt and poetry.lock, prefer poetry.lock.
function deduplicate(lockFiles) {
    const byDir = new Map();
    for (const lf of lockFiles) {
        const dir = path.dirname(lf.path);
        if (!byDir.has(dir)) byDir.set(dir, []);
        byDir.get(dir).push(lf);
    }

    const result = [];
    for (const [, group] of byDir) {
        const npm = pickBest(group.filter((f) => f.ecosystem === 'npm'), ['npm-lock', 'pnpm-lock', 'yarn-lock']);
        const pypi = pickBest(group.filter((f) => f.ecosystem === 'pypi'), ['poetry-lock', 'pipfile-lock', 'requirements']);
        const cargo  = group.find((f) => f.type === 'cargo-lock');
        const golang = group.find((f) => f.type === 'go-modules');
        // gradle.lockfile preferred over pom.xml — it has the full resolved graph
        const java   = pickBest(group.filter((f) => f.ecosystem === 'maven'), ['gradle-lock', 'maven-pom']);
        const nuget    = group.find((f) => f.type === 'nuget-lock');
        const gem      = group.find((f) => f.type === 'gemfile-lock');
        const composer = group.find((f) => f.type === 'composer-lock');
        const swift    = group.find((f) => f.type === 'swift-lock');
        const pub      = group.find((f) => f.type === 'pubspec-lock');
        if (npm)      result.push(npm);
        if (pypi)     result.push(pypi);
        if (cargo)    result.push(cargo);
        if (golang)   result.push(golang);
        if (java)     result.push(java);
        if (nuget)    result.push(nuget);
        if (gem)      result.push(gem);
        if (composer) result.push(composer);
        if (swift)    result.push(swift);
        if (pub)      result.push(pub);
    }
    return result;
}

function pickBest(candidates, preferenceOrder) {
    for (const type of preferenceOrder) {
        const match = candidates.find((c) => c.type === type);
        if (match) return match;
    }
    return null;
}

module.exports = { detect };
