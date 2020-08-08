const restify = require('restify')
const corsMiddleware = require('restify-cors-middleware2')
const morgan = require('morgan')

const { PORT, NODE_ENV } = require('./config')
require('./db')

// Create CORS policy
const cors = corsMiddleware({
    origins: ['*']
})

// Create Server
const server = restify.createServer({
    name: 'Auth',
    version: '1.0.0'
})

// Setup cors
server.pre(cors.preflight)
server.use(cors.actual)

// Throttle server according to CPU usage
server.pre(restify.plugins.cpuUsageThrottle({
    limit: .8,
    max: .9,
    interval: 500,
    halfLife: 500
}))

// Throttle server for repeated requests
server.use(restify.plugins.throttle({
    burst: 5,
    rate: .5,
    ip: true,
    setHeaders: true
}))

// Setup request response logger
server.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'))

// Setup body parser
server.use(restify.plugins.bodyParser())

// Setup query parser
server.use(restify.plugins.queryParser())

// Setup Routes
require('./routes/routes')(server)

// Listen on port
server.listen(
    PORT,
    console.log(`${NODE_ENV === 'production' ? 'Production' : 'Development'} API Server started on port ${PORT}...`)
)