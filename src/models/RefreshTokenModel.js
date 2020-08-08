const mongoose = require('mongoose')

const RefreshTokenSchema = new mongoose.Schema({
    refreshToken: {
        type: String,
        required: true,
        unique: true
    },
    userId: {
        type: mongoose.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    userAgent: {
        type: String,
        required: true
    },
    type: String,
    browser: String,
    engine: String,
    version: String,
    os: String
}, {
    timestamps: true
})

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema)