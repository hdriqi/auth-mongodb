const jwt = require('jsonwebtoken')
const MongoClient = require('mongodb').MongoClient
const uuidv4 = require('uuid/v4')

module.exports = class Model {
	constructor() {
		this.client = null
		this.accessTokenLifetime = 15 * 60 * 1000
		this.refreshTokenLifetime = 3 * 24 * 60 * 60 * 1000
		this.secretKey = 'hehehehe'

		this.tokenAuthorizationMiddleware = this.tokenAuthorizationMiddleware.bind(this)
		this.clientAuthorizationMiddleware = this.clientAuthorizationMiddleware.bind(this)
		this.authentication = this.authentication.bind(this)

		this.init()
	}

	async init() {
		// const url = process.env.MONGO_URL || 'mongodb+srv://2I6X86RIS0A7YXP1:Sl8WP3YPp9h6GjqD@vx-cluster0-sjeib.mongodb.net/test?retryWrites=true&w=majority'
		const url = process.env.MONGO_URL || 'mongodb://localhost:27017/retryWrites=true&w=majority'
		this.client = await MongoClient.connect(url, { 
			useNewUrlParser: true,
			useUnifiedTopology: true
		})
	}

	async authorization(type, payload) {
		let responseData = null

		if(type === 'clientCredential') {
			// check if payload.clientId && payload.clientSecret match in database
			const data = await this.client.db('auth').collection('clients').findOne({
				clientId: payload.clientId,
				clientSecret: payload.clientSecret
			})

			if(!data) {
				return {
					status: 'error',
					message: 'invalid client credential'
				}
			}

			responseData = data
		}
		else if(type === 'accessToken') {
			// check if jwt valid
			if(payload.accessToken.length === 0) {
				return {
					status: 'error',
					message: 'unauthorized'
				}
			}

			const [head, token] = payload.accessToken.split(' ')
			if(head !== 'Bearer') {
				return {
					status: 'error',
					message: 'unauthorized'
				}
			}

			try {
				const response = await jwt.verify(token, this.secretKey)
			} catch (err) {
				return {
					status: 'error',
					message: 'unauthorized'
				}
			}
		}

		return {
			status: 'success',
			data: {}
		}
	}

	async tokenAuthorizationMiddleware(req, res, next) {
		const payload = {
			accessToken: req.headers['authorization']
		}

		const response = await this.authorization('accessToken', payload)

		if(response.status === 'success') {
			return next()
		}

		return res.json(response)
	}

	async clientAuthorizationMiddleware(req, res, next) {
		const payload = {
			clientId: req.headers['x-client-id'],
			clientSecret: req.headers['x-client-secret']
		}

		const response = await this.authorization('clientCredential', payload)

		if(response.status === 'success') {
			return next()
		}

		return res.json(response)
	}


	async confirmAuthentication(token) {
		const data = await this.client.db('auth').collection('confirmations').findOne({
			token: token
		})
		if(!data) {
			return {
				status: 'error',
				message: 'invalid token'
			}
		}
		if(data.expiresInTs < new Date().getTime()) {
			return {
				status: 'error',
				message: 'expired token'
			}
		}
		const payload = JSON.parse(data.payload)

		if(data.type === 'CONFIRM_LOGIN') {
			await this.client.db('auth').collection('tokens').findOneAndUpdate({
				refreshToken: payload.refreshToken
			}, {
				$set: {
					status: 'active'
				}
			})
		}

		return {
			status: 'success',
			data: {}
		}
	}

	async authentication(type, payload) {
		let userUid = null

		if(type === 'refreshToken') {
			// check token in database
			// reject if payload.refreshToken is not exist
			// reject if token.status === expired || currentDate - token.lastActivityTs > 24h
			const token = await this.client.db('auth').collection('tokens').findOne({
				refreshToken: payload.refreshToken
			})

			
			if(!token || token.status === 'inactive') {
				return {
					status: 'error',
					message: 'invalid token'
				}
			}
			if(token.refreshTokenExpiresInTs < new Date().getTime()) {
				const x = await this.client.db('auth').collection('tokens').findOneAndUpdate({
					refreshToken: payload.refreshToken
				}, {
					$set: {
						status: 'inactive'
					}
				})

				return {
					status: 'error',
					message: 'expired token'
				}
			}

			userUid = token.userUid
		}
		else if(type === 'password') {
			// reject if payload.email && payload.password is not match
			const data = await this.client.db('auth').collection('users').findOne({
				email: payload.email,
				password: payload.password
			})
			if(!data) {
				return {
					status: 'error',
					message: 'invalid email or password'
				}
			}

			userUid = data.uid
		}
		else {
			return {
				status: 'error',
				message: 'invalid authentication type'
			}
		}

		// generate access token & refresh token
		const refreshToken = uuidv4()
		const accessToken = await jwt.sign({
			userUid: userUid,
			exp: (new Date().getTime() + this.accessTokenLifetime) / 1000
		}, this.secretKey)

		const response = await this.client.db('auth').collection('tokens').insertOne({
			userUid: userUid,
			accessToken: accessToken,
			expiresInTs: new Date().getTime() + this.accessTokenLifetime,
			refreshToken: refreshToken,
			refreshTokenExpiresInTs: new Date().getTime() + this.refreshTokenLifetime,
			status: 'inactive'
		})

		const responseData = response.ops[0]

		// only send refreshToken for type password
		if(type === 'password') {
			delete responseData.accessToken
			delete responseData.expiresInTs

			// 2FA email
			const confToken = uuidv4()
			await this.client.db('auth').collection('confirmations').insertOne({
				token: confToken,
				type: 'CONFIRM_LOGIN',
				payload: JSON.stringify({
					refreshToken: refreshToken
				}),
				expiresInTs: new Date().getTime() + (15 * 60 * 1000)
			})

			// send email with confToken
		}

		return {
			status: 'success',
			data: responseData
		}
	}
}