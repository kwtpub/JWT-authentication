const config = require('../config');
const ApiError = require('../exceptions/api-error');

module.exports = function requireTrustedOrigin(req, res, next) {
    // Browsers control Origin. Reject absent/null origins too, including login CSRF.
    if (req.get('Origin') !== config.clientOrigin) {
        return next(ApiError.Forbidden('Untrusted request origin'));
    }
    next();
};
