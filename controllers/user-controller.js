const userService = require('../service/user-service');

class UserController {
    async registration(req, res, next) {
        try {
            console.log('Запрос на регистрацию:', req.body);
            const {email, password} = req.body;
            
            if (!email || !password) {
                return res.status(400).json({message: 'Email и пароль обязательны'});
            }
            
            console.log('Начало процесса регистрации для:', email);
            const userData = await userService.registration(email, password);
            console.log('Регистрация успешна для:', email);
            
            res.cookie('refreshToken', userData.refreshToken, {maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true});
            return res.json(userData);
        } catch (e) {
            console.error('Ошибка регистрации:', e.message);
            return next(e);
        }
    }

    async login(req, res, next) {
        try {

        } catch (e) {

        }
    }

    async logout(req, res, next) {
        try {

        } catch (e) {

        }
    }

    async activate(req, res, next) {
        try {

        } catch (e) {

        }
    }

    async refresh(req, res, next) {
        try {

        } catch (e) {

        }
    }

    getUsers(req, res, next) {
        try {
            res.json(['123', '456']);
        } catch (e) {

        }
    }


}

module.exports = new UserController();