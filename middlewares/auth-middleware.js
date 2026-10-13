const ApiError = require('../exceptions/api-error');
const tokenService = require('../service/token-service');

module.exports = async function authenticate(req, res, next) {
    try {
        const header = req.get('Authorization');
        const match = typeof header === 'string' && /^Bearer ([^ ]+)$/i.exec(header);
        const claims = match && tokenService.validateAccessToken(match[1]);
        if (!claims || !await tokenService.findSession(claims.sub, claims.sid)) {
            return next(ApiError.UnauthorizedError());
        }
        req.user = claims;
        return next();
    } catch (error) { return next(error); }
};
