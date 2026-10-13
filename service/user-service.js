const User = require('../models/user-model');
const bcrypt = require('bcrypt');
const { randomBytes } = require('node:crypto');
const mailService = require('./mail-service');
const tokenService = require('./token-service');
const ApiError = require('../exceptions/api-error');
const UserDto = require('../dtos/user-dto');
const config = require('../config');

// Same bcrypt work for unknown users; don't create a fresh dummy hash per request.
const dummyHash = bcrypt.hashSync(randomBytes(32).toString('hex'), config.bcryptCost);
const registrationMessage = { message: 'If registration is available, an activation email will be sent' };

class UserService {
    async registration(email, password) {
        if (await User.exists({ email })) return registrationMessage;
        const passwordHash = await bcrypt.hash(password, config.bcryptCost);
        const activationToken = randomBytes(32).toString('hex');
        let user;
        try {
            user = await User.create({
                email, password: passwordHash,
                activationTokenHash: tokenService.hash(activationToken),
                activationExpiresAt: new Date(Date.now() + config.activationTtl),
            });
        } catch (error) {
            if (error.code === 11000) return registrationMessage;
            throw error;
        }
        try {
            await mailService.sendActivationMail(email, config.apiOrigin + '/api/activate/' + activationToken);
        } catch {
            // A failed delivery must not strand a new pending account permanently.
            await User.deleteOne({ _id: user._id, isActivated: false });
            throw ApiError.ServiceUnavailable();
        }
        return registrationMessage;
    }

    async activate(token) {
        const user = await User.findOneAndUpdate({
            activationTokenHash: tokenService.hash(token),
            activationExpiresAt: { $gt: new Date() }, isActivated: false,
        }, {
            $set: { isActivated: true },
            $unset: { activationTokenHash: '', activationExpiresAt: '', activationLink: '' },
        }, { new: true, strict: false });
        if (!user) throw ApiError.BadRequest('Invalid or expired activation link');
    }

    async resendActivation(email) {
        const token = randomBytes(32).toString('hex');
        const now = Date.now();
        // A per-account cooldown also covers migrated pending accounts with no token.
        const user = await User.findOneAndUpdate({
            email, isActivated: false,
            $or: [
                { activationExpiresAt: { $lte: new Date(now + config.activationTtl - 60000) } },
                { activationExpiresAt: { $exists: false } },
            ],
        }, { $set: {
            activationTokenHash: tokenService.hash(token),
            activationExpiresAt: new Date(now + config.activationTtl),
        } }, { new: true });
        if (user) {
            try { await mailService.sendActivationMail(user.email, config.apiOrigin + '/api/activate/' + token); }
            catch { throw ApiError.ServiceUnavailable(); }
        }
        return registrationMessage;
    }

    async login(email, password) {
        const user = await User.findOne({ email }).select('+password');
        const matches = await bcrypt.compare(password, user ? user.password : dummyHash);
        if (!user || !matches || !user.isActivated) throw ApiError.InvalidCredentials();
        if (bcrypt.getRounds(user.password) < config.bcryptCost) {
            user.password = await bcrypt.hash(password, config.bcryptCost);
            await user.save();
        }
        return { ...await tokenService.createSession(user._id), user: new UserDto(user) };
    }

    async logout(refreshToken) {
        await tokenService.revoke(refreshToken);
    }

    async refresh(refreshToken) {
        const claims = tokenService.validateRefreshToken(refreshToken);
        if (!claims) throw ApiError.UnauthorizedError();
        const user = await User.findById(claims.sub);
        if (!user || !user.isActivated) throw ApiError.UnauthorizedError();
        const tokens = await tokenService.rotate(refreshToken, claims);
        if (!tokens) throw ApiError.UnauthorizedError();
        return { ...tokens, user: new UserDto(user) };
    }

    async getMe(userId) {
        const user = await User.findById(userId);
        if (!user || !user.isActivated) throw ApiError.UnauthorizedError();
        return new UserDto(user);
    }
}

module.exports = new UserService();
