const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const errors = require('restify-errors')
const DeviceDetector = require('device-detector')

const { JWT_SECRET, JWT_REFRESH_SECRET } = require('../config')
const { User, RefreshToken, UserSignInLog } = require('../models')
const { authToken } = require('../middlewares')

module.exports = server => {
    // Sign In
    server.post('/auth', signIn)

    // Sign Out
    server.del('/auth', authToken, signOut)

    // Refresh Token
    server.post('/auth/refresh', refreshToken)

    // Get all active sessions
    server.get('/auth/sessions', authToken, getActiveSessions)

    // Remove all active sessions
    server.del('/auth/sessions', authToken, removeActiveSessions)

    // Update password
    server.post('/auth/updatepassword', authToken, updatePassword)
}

async function signIn(req, res, next) {
    try {
        if (!req.headers['user-agent'])
            return next(new errors.InvalidHeaderError('user-agent is required in headers!'))

        const { username, password } = req.body

        if (!username || !password)
            return next(new errors.BadRequestError('email and password is required!'))

        const user = await User.findOne({ username })

        if (!user)
            return next(new errors.InvalidCredentialsError('Invalid username or password!'))

        if (!(await bcrypt.compare(password.trim(), user.password)))
            return next(new errors.InvalidCredentialsError('Invalid username or password!'))

        const userAgent = req.headers['user-agent']
        const { type, browser, engine, version, os } = DeviceDetector.parse(userAgent)

        const refreshToken = jwt.sign({
            _id: user._id
        }, JWT_REFRESH_SECRET)

        await RefreshToken.create({ refreshToken, userId: user._id, userAgent, type, browser, engine, version, os })

        const iat = Math.floor(Date.now() / 1000)
        const exp = Math.floor(Date.now() / 1000) + (60 * 30) // 30 minutes
        const token = jwt.sign({
            iat,
            _id: user._id,
            exp
        }, JWT_SECRET)

        await UserSignInLog.create({
            userId: user._id,
            userAgent
        })

        res.send({ data: { userId: user._id, token, refreshToken, issuedAt: iat, expiresAt: exp } })
        return next()
    } catch (err) {
        console.log(err)
        return next(err)
    }
}

async function signOut(req, res, next) {
    try {
        const { refreshToken } = req.body

        if (!refreshToken)
            return next(new errors.BadRequestError('refreshToken is required!'))

        const user = jwt.verify(refreshToken, JWT_REFRESH_SECRET)

        const foundRefreshToken = await RefreshToken.findOne({ userId: user._id, refreshToken })

        if (!foundRefreshToken)
            return next(new errors.InvalidCredentialsError('Invalid Refresh Token!'))

        await foundRefreshToken.remove()

        res.send(204)
        return next()
    } catch (err) {
        if (err.name === 'JsonWebTokenError')
            return next(new errors.InvalidCredentialsError('Invalid Refresh Token!'))
        console.log(err)
        return next(err)
    }
}

async function refreshToken(req, res, next) {
    try {
        const { refreshToken } = req.body

        if (!refreshToken)
            return next(new errors.BadRequestError('refreshToken is required!'))

        const user = jwt.verify(refreshToken, JWT_REFRESH_SECRET)

        const foundRefreshToken = await RefreshToken.findOne({
            userId: user._id,
            refreshToken
        })
        if (!foundRefreshToken)
            return next(new errors.InvalidCredentialsError('Invalid Authorization Token!'))

        const newRefreshToken = jwt.sign({
            _id: user._id
        }, JWT_REFRESH_SECRET)

        foundRefreshToken.refreshToken = newRefreshToken
        await foundRefreshToken.save()

        const iat = Math.floor(Date.now() / 1000)
        const exp = Math.floor(Date.now() / 1000) + (60 * 30)
        const newToken = jwt.sign({
            iat,
            _id: user._id,
            exp
        }, JWT_SECRET)

        res.send({ data: { userId: user._id, token: newToken, refreshToken: newRefreshToken, issuedAt: iat, expiresAt: exp } })
        return next()
    } catch (err) {
        if (err.name === 'JsonWebTokenError')
            return next(new errors.InvalidCredentialsError('Invalid Authorization Token!'))
        console.log(err)
        return next(err)
    }
}

async function getActiveSessions(req, res, next) {
    try {
        const sessions = await RefreshToken.find({ userId: req.user._id })
        res.send({ data: { sessions: sessions.map(transformSession) } })
        return next()
    } catch (err) {
        console.log(err)
        return next(err)
    }
}

async function removeActiveSessions(req, res, next) {
    try {
        const { refreshToken } = req.body

        if (!refreshToken)
            return next(new errors.BadRequestError('refreshToken is required!'))

        const user = jwt.verify(refreshToken, JWT_REFRESH_SECRET)

        if (!(await RefreshToken.findOne({ userId: user._id, refreshToken })))
            return next(new errors.InvalidCredentialsError('Invalid Refresh Token!'))

        await RefreshToken.deleteMany({ userId: req.user._id })

        res.send(204)
        return next()
    } catch (err) {
        if (err.name === 'JsonWebTokenError')
            return next(new errors.InvalidCredentialsError('Invalid Refresh Token!'))
        console.log(err)
        return next(err)
    }
}

async function updatePassword(req, res, next) {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body

        if (!currentPassword)
            return next(new errors.BadRequestError('Current password is required!'))
        if (!newPassword)
            return next(new errors.BadRequestError('New password is required!'))
        if (!confirmPassword)
            return next(new errors.BadRequestError('Confirm password is required!'))
        if (newPassword !== confirmPassword)
            return next(new errors.BadRequestError('New password and confirm password must be same!'))
        if (currentPassword === newPassword)
            return next(new errors.BadRequestError('Current password and new password cannot be same!'))

        const user = await User.findById(req.user._id)

        if (!user)
            return next(new errors.NotFoundError('User Not Found!'))

        if (!(await bcrypt.compare(currentPassword, user.password)))
            return next(new errors.BadRequestError('Current password is invalid!'))

        user.password = await bcrypt.hash(newPassword, 10)
        user.passwordUpdatedAt = new Date()

        user.save()

        res.send(200)
        return next()
    } catch (err) {
        console.log(err)
        return next(err)
    }
}

function transformSession(session) {
    return {
        type: session.type,
        browser: session.browser,
        engine: session.engine,
        version: session.version,
        os: session.os,
        userAgent: session.userAgent,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt
    }
}