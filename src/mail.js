const nodemailer = require('nodemailer')

class Mail {
  constructor() {
    this.transporter = null
  }

  init() {
    console.log(process.env.EMAIL_USER)
    console.log(process.env.EMAIL_PASS)
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
}

const mail = new Mail()

module.exports = mail