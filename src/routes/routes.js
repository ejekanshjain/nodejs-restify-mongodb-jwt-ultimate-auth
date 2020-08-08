module.exports = server => {
    server.get('/', (req, res, next) => {
        res.send({ message: 'Auth Server Up and Running...' })
        next()
    })
    require('./auth')(server)
}