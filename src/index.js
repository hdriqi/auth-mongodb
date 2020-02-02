const express = require('express')
const bodyParser = require('body-parser')
const rateLimit = require('express-rate-limit')
const RedisStore = require('rate-limit-redis')

const Controller = require('./controller')

const PORT = 3000

const app = express()
const ctl = new Controller()

const limiter = rateLimit({
  store: new RedisStore({
    redisURL: `redis://localhost:6379`
  }),
  windowMs: 15 * 60 * 1000,
  max: 100
})

//  apply to all requests
app.use(limiter)

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.post('/auth', ctl.clientAuthorizationMiddleware, async (req, res) => {
  const response = await ctl.authentication(req.body.type, {
    email: req.body.email,
    password: req.body.password,
    refreshToken: req.body.refreshToken
  })
  res.json(response)
})

app.post('/confirm', ctl.clientAuthorizationMiddleware, async (req, res) => {
  const response = await ctl.confirmAuthentication(req.query.token)
  res.json(response)
})

app.post('/verify', ctl.clientAuthorizationMiddleware, ctl.tokenAuthorizationMiddleware, async (req, res) => {
  res.json({
    status: 'success'
  })
})

app.listen(PORT, (err) => {
  if(err) {
    console.log(err)
    process.exit(1)
  }
  console.log(`Serving on PORT ${PORT}`)
})