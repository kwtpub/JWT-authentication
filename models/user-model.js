const { Schema, model } = require('mongoose');

const UserSchema = new Schema({
    email: { type: String, unique: true, required: true, lowercase: true, trim: true },
    isActivated: { type: Boolean, default: false },
    password: { type: String, required: true, select: false },
    activationTokenHash: { type: String, select: false },
    activationExpiresAt: { type: Date, select: false },
}, { timestamps: true });

module.exports = model('User', UserSchema);
