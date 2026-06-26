'use strict';

require('dotenv').config();

if (!process.env.HMAC_SECRET) {
    console.error('[worker] HMAC_SECRET env var is required');
    process.exit(1);
}

const crypto = require('crypto');
const db     = require('../db');
const { claimNextScanJob, markScanDone, markScanFailed, recoverStaleJobs } = require('../services/scanQueue');
const { executeIngestTx }       = require('../services/ingestService');
const { sendScanCompleteEmail, sendVulnAlertIfNew } = require('../services/emailService');
const { osvEnrichAsync }        = require('../services/postIngestAnalysis');
const { parseGitHubTarget, cloneRepoAsync } = require('../../github');
const { generateFromDirectory } = require('../../pipeline');
const { applyKEVAfterIngest }   = require('../../kev');

const WORKER_ID      = `worker-${crypto.randomBytes(4).toString('hex')}`;
const POLL_MS        = Number(process.env.SCAN_WORKER_POLL_MS) || 2000;
const TIMEOUT_MS     = Number(process.env.SCAN_TIMEOUT_MS)     || 180_000;
const RECOVERY_MS    = 60_000;

process.stdout.write(`[worker] ${WORKER_ID} starting — poll=${POLL_MS}ms timeout=${TIMEOUT_MS}ms\n`);

async function runJob(job) {
    const { id: jobId, org_id: orgId, repo, ref } = job;
    let cleanup = null;
    let aborted = false;

    const timeoutHandle = setTimeout(() => {
        aborted = true;
        if (cleanup) { try { cleanup(); cleanup = null; } catch {} }
    }, TIMEOUT_MS);

    try {
        const target = parseGitHubTarget(repo + (ref ? `@${ref}` : ''));
        if (!target) throw new Error('Invalid repository format. Use owner/repo or owner/repo@branch.');

        const cloned = await cloneRepoAsync(target, {});
        cleanup = cloned.cleanup;
        if (aborted) throw new Error('Scan timed out during clone — repository may be too large. Use the CLI.');

        let result;
        try {
            result = await generateFromDirectory(cloned.dir, {
                name:      target.repo,
                version:   ref || cloned.commitSha?.slice(0, 7) || 'unknown',
                vulns:     false,
                licenses:  false,
                recursive: true,
            });
        } catch (pipeErr) {
            throw new Error(pipeErr.message.split('\n')[0]);
        }

        if (aborted) throw new Error('Scan timed out during analysis.');

        cleanup();
        cleanup = null;

        const appName = target.repo;
        const { sbomId, purlToCompId, appId } = await db.tx((client) =>
            executeIngestTx(client, orgId, appName, {
                version:   ref || cloned.commitSha?.slice(0, 7) || 'unknown',
                commit:    cloned.commitSha,
                branch:    ref || null,
                cyclonedx: result.cyclonedx,
                spdx:      result.spdx,
                stats:     result.stats,
                aibom:     result.aiBom || null,
            })
        );

        await markScanDone(jobId, appName, sbomId);

        sendScanCompleteEmail(orgId, appName, result.stats, cloned.commitSha).catch(() => {});

        if (purlToCompId.size > 0) {
            osvEnrichAsync(orgId, result.cyclonedx.components.filter(c => c.purl), purlToCompId)
                .then(() => {
                    applyKEVAfterIngest(orgId);
                    return sendVulnAlertIfNew(orgId, appId, appName);
                })
                .catch(err => console.error('[worker/osv]', err.message));
        }

        console.log(`[worker] job=${jobId} done app=${appName}`);
    } catch (err) {
        if (cleanup) { try { cleanup(); } catch {} }
        const msg = aborted
            ? 'Scan timed out — repository may be too large. Use the CLI for large repos.'
            : err.message;
        await markScanFailed(jobId, msg);
        console.error(`[worker] job=${jobId} failed:`, msg);
    } finally {
        clearTimeout(timeoutHandle);
    }
}

let lastRecovery = 0;

async function poll() {
    try {
        const now = Date.now();
        if (now - lastRecovery > RECOVERY_MS) {
            lastRecovery = now;
            await recoverStaleJobs(TIMEOUT_MS).catch(err =>
                console.error('[worker/recovery]', err.message)
            );
        }

        const job = await claimNextScanJob(WORKER_ID);
        if (job) {
            console.log(`[worker] claimed job=${job.id} repo=${job.repo}`);
            await runJob(job);
        }
    } catch (err) {
        console.error('[worker/poll]', err.message);
    }

    setTimeout(poll, POLL_MS);
}

poll();
