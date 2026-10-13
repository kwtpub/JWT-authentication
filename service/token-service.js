const jwt = require('jsonwebtoken');
const { randomUUID, createHash } = require('node:crypto');
const Token = require('../models/token-model');
const config = require('../config');

class TokenService {
    hash(token) {
        return createHash('sha256').update(token).digest('hex');
    }

    generateTokens(userId, sessionId, expiresAt) {
        const refreshLifetime = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
        if (refreshLifetime < 1) throw new Error('Session expired');
        const payload = { type: 'access', sid: sessionId };
        const common = { algorithm: 'HS256', subject: String(userId), issuer: config.issuer };
        return {
            accessToken: jwt.sign(payload, config.accessSecret, {
                ...common, audience: config.accessAudience,
                expiresIn: config.accessTtl, jwtid: randomUUID(),
            }),
            refreshToken: jwt.sign({ type: 'refresh', sid: sessionId }, config.refreshSecret, {
                ...common, audience: config.refreshAudience,
                expiresIn: refreshLifetime, jwtid: randomUUID(),
            }),
        };
    }

    validate(token, type) {
        if (typeof token !== 'string' || token.length > 4096) return null;
        try {
            const claims = jwt.verify(token, type === 'access' ? config.accessSecret : config.refreshSecret, {
                algorithms: ['HS256'], issuer: config.issuer,
                audience: type === 'access' ? config.accessAudience : config.refreshAudience,
            });
            if (claims.type !== type || typeof claims.sub !== 'string' || !/^[a-f0-9]{24}$/.test(claims.sub) ||
                typeof claims.sid !== 'string' || !/^[a-f0-9-]{36}$/.test(claims.sid) ||
                typeof claims.jti !== 'string' || !Number.isInteger(claims.exp) ||
                !Number.isInteger(claims.iat)) return null;
            return claims;
        } catch {
            return null;
        }
    }

    validateAccessToken(token) { return this.validate(token, 'access'); }
    validateRefreshToken(token) { return this.validate(token, 'refresh'); }

    async createSession(userId) {
        const sessionId = randomUUID();
        const expiresAt = new Date(Date.now() + config.refreshTtl * 1000);
        const tokens = this.generateTokens(userId, sessionId, expiresAt);
        await Token.findOneAndUpdate({ user: userId }, {
            $set: { sessionId, expiresAt, tokenHash: this.hash(tokens.refreshToken) },
            // Remove sensitive fields if a legacy session record is replaced.
            $unset: { refreshToken: '' },
        }, { upsert: true, new: true, runValidators: true, strict: false });
        return { ...tokens, expiresAt };
    }

    async findSession(userId, sessionId) {
        return Token.findOne({ user: userId, sessionId, expiresAt: { $gt: new Date() } });
    }

    async rotate(refreshToken, claims) {
        const session = await this.findSession(claims.sub, claims.sid);
        if (!session) return null;
        const tokens = this.generateTokens(claims.sub, claims.sid, session.expiresAt);
        // Compare-and-swap: at most one request can consume the current token.
        const updated = await Token.findOneAndUpdate({
            user: claims.sub, sessionId: claims.sid,
            tokenHash: this.hash(refreshToken), expiresAt: { $gt: new Date() },
        }, { $set: { tokenHash: this.hash(tokens.refreshToken) } }, { new: true });
        if (!updated) {
            // A valid but consumed token signals replay; revoke this family only.
            await Token.deleteOne({ user: claims.sub, sessionId: claims.sid });
            return null;
        }
        return { ...tokens, expiresAt: updated.expiresAt };
    }

    async revoke(refreshToken) {
        const claims = this.validateRefreshToken(refreshToken);
        if (!claims) return;
        await Token.deleteOne({
            user: claims.sub, sessionId: claims.sid, tokenHash: this.hash(refreshToken),
        });
    }
}

module.exports = new TokenService();
