const mongoose = require('mongoose')

const { MONGODB_URL } = require('../config')

mongoose
    .connect(MONGODB_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true
    })
    .then(() => console.log('Connected to MongoDB...'))
    .catch(err => {
        console.log(err)
        process.exit(1)
    })

module.exports = mongoose.connection