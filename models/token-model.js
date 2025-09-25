const { Schema, model, Types } = require('mongoose');

const TokenUserSchema = new Schema({
    user: {type: Types.ObjectId, ref: 'User', required: true},
    refreshToken: {type: String, required: true},
})

module.exports = model('Token', TokenUserSchema);