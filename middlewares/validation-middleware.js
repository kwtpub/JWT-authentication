const { validationResult } = require('express-validator');
const ApiError = require('../exceptions/api-error');

module.exports = function validate(req, res, next) {
    if (!validationResult(req).isEmpty()) {
        // Validation errors can contain the submitted password; never serialize them.
        return next(ApiError.BadRequest('Invalid request'));
    }
    next();
};
