const errors = require('restify-errors')
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../config')

module.exports = (req, res, next) => {
    try {
        if (!req.headers['authorization'])
            throw new Error('Authorization Token is required!')
        const user = jwt.verify(req.headers['authorization'], JWT_SECRET)
        req.user = user
        return next()
    } catch (err) {
        return next(new errors.InvalidCredentialsError('Invalid Authorization Token!'))
    }
}