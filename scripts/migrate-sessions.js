require('dotenv').config({ quiet: true });
const mongoose = require('mongoose');
const config = require('../config');

async function migrate() {
    try {
        await mongoose.connect(config.dbUrl, { autoIndex: false });
        const collection = mongoose.connection.collection('users');
        const accounts = await collection.find({}, { projection: { _id: 1, email: 1 } }).toArray();
        const seen = new Set();
        const updates = accounts.map(account => {
            const email = account.email.trim().toLowerCase();
            if (seen.has(email)) throw new Error('Email normalization collision');
            seen.add(email);
            return { updateOne: { filter: { _id: account._id }, update: {
                $set: { email },
                $unset: { activationLink: '', activationTokenHash: '', activationExpiresAt: '' },
            } } };
        });
        // Maintenance operation: deliberately signs everyone out, preserves accounts.
        const sessions = await mongoose.connection.collection('tokens').deleteMany({});
        const users = updates.length ? await collection.bulkWrite(updates) : { modifiedCount: 0 };
        console.log('Revoked sessions: ' + sessions.deletedCount);
        console.log('Cleared legacy/pending activation state: ' + users.modifiedCount);
    } finally { await mongoose.disconnect(); }
}

if (require.main === module) {
    migrate().catch(() => {
        console.error('Migration failed; check database access and email normalization collisions without logging credentials');
        process.exitCode = 1;
    });
}

module.exports = { migrate };
