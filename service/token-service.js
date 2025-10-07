const jwt = require('jsonwebtoken');
const TokenModel = require('../models/token-model');

class TokenService {
    generateTokens(payload) { 
        const accessSecret = process.env.JWT_ACCESS_SECRET;
        const refreshSecret = process.env.JWT_REFRESH_SECRET;
        if (!accessSecret || !refreshSecret) {
            throw new Error('JWT secrets are not configured. Set JWT_ACCESS_SECRET and JWT_REFRESH_SECRET in environment.');
        }
        const accessToken = jwt.sign(payload, accessSecret, {expiresIn: '30s'})
        const refreshToken = jwt.sign(payload, refreshSecret, {expiresIn: '30d'})
        return {
            accessToken,
            refreshToken
        }
    }
    
    validateAccessToken(token) {
    try {
        const userData = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        return userData;
    } catch(e) {

    }
  }

    async saveToken(userId, refreshToken) {
        const tokenData = await TokenModel.findOne({user: userId})
        if (tokenData) {
            tokenData.refreshToken = refreshToken;
            return tokenData.save();
        }
        const token = await TokenModel.create({user: userId, refreshToken})
        return token;
    }

    async removeToken(refreshToken) {
        const token = await TokenModel.deleteOne({refreshToken})
        return token;
    }

    async findToken(refreshToken) {
        const tokenData = await TokenModel.findOne({refreshToken})
        return tokenData;
    }

}

module.exports = new TokenService();
