require('dotenv').config()

module.exports = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 5001,
    MONGODB_URL: process.env.MONGODB_URL || 'mongodb://localhost:27017',
    JWT_SECRET: process.env.JWT_SECRET || 'secret1',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'secret2'
}