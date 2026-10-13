module.exports = class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }

    static UnauthorizedError() { return new ApiError(401, 'Authentication required'); }
    static InvalidCredentials() { return new ApiError(401, 'Invalid email or password'); }
    static Forbidden(message) { return new ApiError(403, message); }
    static BadRequest(message) { return new ApiError(400, message); }
    static ServiceUnavailable() { return new ApiError(503, 'Service temporarily unavailable'); }
};
