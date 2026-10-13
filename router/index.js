const express = require('express');
const { body, param } = require('express-validator');
const { rateLimit } = require('express-rate-limit');
const userController = require('../controllers/user-controller');
const authenticate = require('../middlewares/auth-middleware');
const validate = require('../middlewares/validation-middleware');
const requireTrustedOrigin = require('../middlewares/origin-middleware');

function credentials(registration = false) {
    return [
        body('email').isString().bail().trim().isLength({ max: 254 }).isEmail().bail().toLowerCase(),
        body('password').isString().bail()
            .isLength({ min: registration ? 15 : 1, max: 72 }).bail()
            .custom(value => Buffer.byteLength(value, 'utf8') <= 72),
        validate,
    ];
}
function limiter(limit) {
    return rateLimit({
        windowMs: 15 * 60 * 1000, limit,
        standardHeaders: 'draft-8', legacyHeaders: false,
        message: { message: 'Too many requests; try again later' },
    });
}

module.exports = function createRouter() {
    const router = express.Router();
    // Limit before parsing/hashing: one process, counters keyed by socket IP.
    router.use(limiter(300));
    router.use(express.json({ limit: '10kb' }));
    const loginLimit = limiter(10);
    const registrationLimit = limiter(5);
    const activationLimit = limiter(30);
    const resendLimit = limiter(5);
    router.post('/registration', requireTrustedOrigin, registrationLimit,
        ...credentials(true), userController.registration);
    router.post('/login', requireTrustedOrigin, loginLimit,
        ...credentials(), userController.login);
    router.post('/resend-activation', requireTrustedOrigin, resendLimit,
        body('email').isString().bail().trim().isLength({ max: 254 }).isEmail().bail().toLowerCase(),
        validate, userController.resendActivation);
    router.post('/logout', requireTrustedOrigin, userController.logout);
    router.post('/refresh', requireTrustedOrigin, userController.refresh);
    router.get('/refresh', (req, res) => res.set('Allow', 'POST').status(405).json({ message: 'Use POST' }));
    router.get('/activate/:link', activationLimit,
        param('link').isString().matches(/^[a-f0-9]{64}$/), validate, userController.activate);
    router.get('/me', authenticate, userController.getMe);
    return router;
};
