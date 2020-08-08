const mongoose = require('mongoose')

const UserSignInLogSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    userAgent: {
        type: String,
        required: true
    }
}, {
    timestamps: true
})

module.exports = mongoose.model('UserSignInLog', UserSignInLogSchema)