require('dotenv').config({ quiet: true });
const mongoose = require('mongoose');
const config = require('./config');
const { createApp } = require('./app');
const User = require('./models/user-model');
const Token = require('./models/token-model');

async function start() {
    await mongoose.connect(config.dbUrl);
    await Promise.all([User.init(), Token.init()]);
    return createApp().listen(config.port, () => console.log('API listening on port ' + config.port));
}

if (require.main === module) {
    start().catch(async () => {
        // Connection errors may contain credentials; never print the raw error.
        console.error('API startup failed; check configuration and database connectivity');
        await mongoose.disconnect();
        process.exitCode = 1;
    });
}

module.exports = { start };
