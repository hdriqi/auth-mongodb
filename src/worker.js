const NATS = require('nats')

class Worker {
  constructor(ctl) {
    this.nc = null
    this.ctl = ctl
  }

  async init() {
    this.nc = await NATS.connect({ 
      url: process.env.NATS_URL,
      json: true,
      maxReconnectAttempts: -1, 
      reconnectTimeWait: 250
    })

    this.nc.subscribe('auth.verify.client', async (msg, reply) => {
      if(reply) {
        const response = await this.ctl.clientAuthorization({
          clientId: msg.clientId,
			    clientSecret: msg.clientSecret
        })
        this.nc.publish(reply, response)
        console.log(`auth.verify.client successfully replying`)
      }
    })

    this.nc.subscribe('auth.verify.token', async (msg, reply) => {
      if(reply) {
        const response = await this.ctl.tokenAuthorization({
          accessToken: msg.accessToken
        })
        this.nc.publish(reply, response)
        console.log(`auth.verify.token successfully replying`)
      }
    })
  }
}

module.exports = Worker