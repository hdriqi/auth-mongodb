const nodemailer = require('nodemailer')
const heml = require('heml')
const templates = require('./mailTemplates')

const hemlOpts = {
  validate: 'soft',
  cheerio: {},
  juice: {},
  beautify: {},
  elements: []
}

class Mail {
  constructor() {
    this.transporter = null
    this.send = this.send.bind(this)
  }

  init() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.zoho.com',
			port: 465,
			secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    })
  }

  send(data) {
    if(!this.transporter) {
      throw 'mail is not initialized'
    }
    return new Promise((resolve, reject) => {
      this.transporter.sendMail(data, (err) => {
        if(err) {
          return reject(err)
        }
        return resolve()
      })
    })
  }

  async sendConfirmRegister(payload) {
    const tmpl = templates.confirmRegister(payload.link)
    const { html } = await heml(tmpl, hemlOpts)
    this.send({
      from: `no-reply@vestrade.io`,
      to: payload.email,
      subject: `[Vestrade] Register Verification`,
      html: html
    })
  }

  async sendConfirmLogin(payload) {
    const tmpl = templates.confirmLogin(payload.link)
    const { html } = await heml(tmpl, hemlOpts)
    this.send({
      from: `no-reply@vestrade.io`,
      to: payload.email,
      subject: `[Vestrade] Login Verification`,
      html: html
    })
  }

  async sendResetPassword(payload) {
    const tmpl = templates.resetPassword(payload.link)
    const { html } = await heml(tmpl, hemlOpts)
    this.send({
      from: `no-reply@vestrade.io`,
      to: payload.email,
      subject: `[Vestrade] Reset Password`,
      html: html
    })
  }
}

const mail = new Mail()

module.exports = mail