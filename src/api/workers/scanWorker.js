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

function logJob(fields) {
    const parts = Object.entries(fields).map(([k, v]) => `${k}=${v}`);
    console.log(`[worker] ${parts.join(' ')}`);
}

async function runJob(job) {
    const { id: jobId, org_id: orgId, repo, ref } = job;
    const startedAt = Date.now();
    let cleanup = null;

    const ac = new AbortController();
    const timeoutHandle = setTimeout(() => ac.abort(), TIMEOUT_MS);

    try {
        const target = parseGitHubTarget(repo + (ref ? `@${ref}` : ''));
        if (!target) throw new Error('Invalid repository format. Use owner/repo or owner/repo@branch.');

        const cloned = await cloneRepoAsync(target, { signal: ac.signal });
        cleanup = cloned.cleanup;

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

        const elapsed = Date.now() - startedAt;
        const components = result.stats?.totalComponents ?? 0;
        logJob({ job: jobId, org: orgId, repo, status: 'done', elapsed: `${elapsed}ms`, components, worker: WORKER_ID });

        sendScanCompleteEmail(orgId, appName, result.stats, cloned.commitSha).catch(() => {});

        if (purlToCompId.size > 0) {
            osvEnrichAsync(orgId, result.cyclonedx.components.filter(c => c.purl), purlToCompId)
                .then(() => {
                    applyKEVAfterIngest(orgId);
                    return sendVulnAlertIfNew(orgId, appId, appName);
                })
                .catch(err => console.error('[worker/osv]', err.message));
        }
    } catch (err) {
        if (cleanup) { try { cleanup(); } catch {} }
        const elapsed = Date.now() - startedAt;
        const isTimeout = ac.signal.aborted || /timed out|timeout/i.test(err.message);
        const status = isTimeout ? 'timed_out' : 'failed';
        const reason = isTimeout
            ? 'Scan timed out — repository may be too large. Use the CLI for large repos.'
            : err.message;
        await markScanFailed(jobId, reason, status);
        logJob({ job: jobId, org: orgId, repo, status, elapsed: `${elapsed}ms`, reason: `"${reason.slice(0, 120)}"`, worker: WORKER_ID });
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
            logJob({ job: job.id, org: job.org_id, repo: job.repo, status: 'claimed', worker: WORKER_ID });
            await runJob(job);
        }
    } catch (err) {
        console.error('[worker/poll]', err.message);
    }

    setTimeout(poll, POLL_MS);
}

poll();
