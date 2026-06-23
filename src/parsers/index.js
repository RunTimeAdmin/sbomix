'use strict';

const { parsePackageLock, parseYarnLock } = require('./npm');
const { parsePoetryLock, parsePipfileLock, parseRequirementsTxt } = require('./python');
const { parseCargoLock } = require('./cargo');
const { parseGoModules } = require('./golang');
const path = require('path');

/**
 * Parse a single detected lock file.
 * @param {{ type: string, path: string }} lockFile
 * @returns {Array<object>} components
 */
function parseLockFile(lockFile) {
    switch (lockFile.type) {
        case 'npm-lock':    return parsePackageLock(lockFile.path);
        case 'yarn-lock':   return parseYarnLock(lockFile.path);
        case 'pnpm-lock':
            console.warn('[packrai] pnpm-lock.yaml support is coming — skipping for now');
            return [];
        case 'poetry-lock': return parsePoetryLock(lockFile.path);
        case 'pipfile-lock':return parsePipfileLock(lockFile.path);
        case 'requirements':return parseRequirementsTxt(lockFile.path);
        case 'cargo-lock':  return parseCargoLock(lockFile.path);
        case 'go-modules':  return parseGoModules(path.dirname(lockFile.path));
        default:
            console.warn(`[packrai] Unknown lock file type: ${lockFile.type}`);
            return [];
    }
}

module.exports = { parseLockFile };
