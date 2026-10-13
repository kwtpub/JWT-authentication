const { Schema, model, Types } = require('mongoose');

// Deliberately one active session per user. Login replaces the previous session.
const TokenSchema = new Schema({
    user: { type: Types.ObjectId, ref: 'User', required: true, unique: true },
    sessionId: { type: String, required: true },
    tokenHash: { type: String, required: true, select: false },
    expiresAt: { type: Date, required: true },
});
TokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = model('Token', TokenSchema);
