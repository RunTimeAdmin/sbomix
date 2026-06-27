'use strict';

require('dotenv').config();

if (!process.env.HMAC_SECRET) {
    console.error('[sbomix] HMAC_SECRET env var is required. Generate one with:\n' +
        '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

const app  = require('./app');
const { startKEVRefresh } = require('../kev');

const PORT = process.env.PORT || 3080;
app.listen(PORT, () => {
    process.stdout.write(`SBOMix API listening on :${PORT}\n`);
    if (process.env.KATZILLA_API_KEY) startKEVRefresh();
});
