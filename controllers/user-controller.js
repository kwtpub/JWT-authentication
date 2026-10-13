const userService = require('../service/user-service');
const config = require('../config');

const cookieOptions = {
    httpOnly: true, secure: config.production, sameSite: 'strict', path: '/api',
};
function clearRefreshCookie(res) {
    res.clearCookie('refreshToken', cookieOptions);
}
function sendSession(res, session) {
    res.cookie('refreshToken', session.refreshToken, {
        ...cookieOptions, expires: session.expiresAt,
    });
    // The refresh token never crosses into a JavaScript-readable response body.
    return res.json({ accessToken: session.accessToken, user: session.user });
}

class UserController {
    async registration(req, res, next) {
        try {
            const result = await userService.registration(req.body.email, req.body.password);
            return res.status(202).json(result);
        } catch (error) { next(error); }
    }

    async login(req, res, next) {
        try {
            return sendSession(res, await userService.login(req.body.email, req.body.password));
        } catch (error) { next(error); }
    }

    async resendActivation(req, res, next) {
        try { return res.status(202).json(await userService.resendActivation(req.body.email)); }
        catch (error) { next(error); }
    }

    async logout(req, res, next) {
        try {
            await userService.logout(req.cookies.refreshToken);
            clearRefreshCookie(res);
            return res.status(204).end();
        } catch (error) { next(error); }
    }

    async activate(req, res, next) {
        try {
            await userService.activate(req.params.link);
            return res.redirect(303, config.clientOrigin);
        } catch (error) { next(error); }
    }

    async refresh(req, res, next) {
        try {
            return sendSession(res, await userService.refresh(req.cookies.refreshToken));
        } catch (error) {
            if (error.status === 401) clearRefreshCookie(res);
            next(error);
        }
    }

    async getMe(req, res, next) {
        try { return res.json(await userService.getMe(req.user.sub)); }
        catch (error) { next(error); }
    }
}

module.exports = new UserController();
