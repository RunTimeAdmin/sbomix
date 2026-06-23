'use strict';

const { parsePackageLock, parseYarnLock } = require('./npm');
const { parsePoetryLock, parsePipfileLock, parseRequirementsTxt } = require('./python');
const { parseCargoLock } = require('./cargo');
const { parseGoModules } = require('./golang');
const { parsePnpmLock }  = require('./pnpm');
const { parsePomXml }        = require('./maven');
const { parseGradleLock }    = require('./gradle');
const { parsePackagesLock }  = require('./dotnet');
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
        case 'pnpm-lock':   return parsePnpmLock(lockFile.path);
        case 'poetry-lock': return parsePoetryLock(lockFile.path);
        case 'pipfile-lock':return parsePipfileLock(lockFile.path);
        case 'requirements':return parseRequirementsTxt(lockFile.path);
        case 'cargo-lock':  return parseCargoLock(lockFile.path);
        case 'go-modules':  return parseGoModules(path.dirname(lockFile.path));
        case 'maven-pom':   return parsePomXml(lockFile.path);
        case 'gradle-lock': return parseGradleLock(lockFile.path);
        case 'nuget-lock':  return parsePackagesLock(lockFile.path);
        default:
            console.warn(`[packrai] Unknown lock file type: ${lockFile.type}`);
            return [];
    }
}

module.exports = { parseLockFile };
