const ApiError = require('./api-error');

module.exports = function errorMiddleware(error, req, res, next) {
    if (res.headersSent) return next(error);
    if (error instanceof ApiError) return res.status(error.status).json({ message: error.message });
    if (error.type === 'entity.too.large') return res.status(413).json({ message: 'Request too large' });
    if (error.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON' });
    // Never log/return full request, database, SMTP, token, or validation errors.
    console.error('Unhandled API error');
    return res.status(500).json({ message: 'Internal server error' });
};
