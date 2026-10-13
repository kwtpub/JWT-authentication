module.exports = class UserDto {
    constructor(user) {
        this.id = String(user._id);
        this.email = user.email;
        this.isActivated = user.isActivated;
    }
};
