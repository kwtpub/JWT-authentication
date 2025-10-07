const UserModel = require('../models/user-model');

const bcrypt = require('bcrypt');
const uuid = require('uuid');
const mailService = require('./mail-service');
const tokenService = require('./token-service');
const ApiError = require('../exceptions/api-error');
const UserDto = require('../dtos/user-dto');


class UserService {
    async registration(email, password) {
        const candidate = await UserModel.findOne({email});
        if (candidate) {
            throw ApiError.BadRequest(`Пользователь с почтой ${email} уже существует`);
        }
        const hashPassword = await bcrypt.hash(password, 3);
        const activationLink = uuid.v4();
        const user = await UserModel.create({email, password: hashPassword, activationLink});
        
        // Отправляем email без ожидания, чтобы избежать таймаута
        try {
            await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`);
        } catch (emailError) {
            console.warn('Ошибка отправки email активации:', emailError.message);
            // Продолжаем работу даже если email не отправился
        }

        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return {...tokens, user: userDto}

    }
    async activate(activationLink) {
        const user = await UserModel.findOne({activationLink});
        if (!user) {
            throw new Error('Пользователь не найден');
        }
        user.isActivated = true;
        await user.save();
    }
    async login(email, password) {
        const user = await UserModel.findOne({email});
        if (!user) {
            throw ApiError.BadRequest('Пользователь с такой почтой не найден');
        }
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            throw ApiError.BadRequest('Неверный пароль');
        }
        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});

        await tokenService.saveToken(userDto.id, tokens.refreshToken);
        return {...tokens, user: userDto}
    }
    
    async logout(refreshToken) {
        const token = await tokenService.removeToken(refreshToken);
        return token;
    }

    async refresh(refreshToken) {
      if(!refreshToken) {
        throw ApiError.UnauthorizedError();
      }
      const userData = tokenService.validateAccessToken(refreshToken);
      const tokenFromDb = await tokenService.findToken(refreshToken);
      if(!userData || !tokenFromDb) {
        throw ApiError.UnauthorizedError();
      }
      const user = await UserModel.findById(userData.id);
      const userDto = new UserDto(user);
      const tokens = tokenService.generateTokens({...userDto});
      await tokenService.saveToken(userDto.id, tokens.refreshToken);
      return {...tokens, user: userDto}
  }
}

module.exports = new UserService();
