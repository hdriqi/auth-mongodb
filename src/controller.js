const jwt = require('jsonwebtoken')
const MongoClient = require('mongodb').MongoClient
const uuidv4 = require('uuid/v4')
const Cryptr = require('cryptr')
const ms = require('ms')
const bcrypt = require('bcryptjs')
const schemas = require('./schemas')
const mail = require('./mail')

module.exports = class Model {
	constructor() {
		this.client = null
		this.accessTokenLifetime = 15 * 60 * 1000
		this.refreshTokenLifetime = 3 * 24 * 60 * 60 * 1000
		this.secretKey = process.env.JWT_SECRET
		this.salt = bcrypt.genSaltSync(10)
		this.cryptr = new Cryptr(process.env.CRYPTR_SECRET)

		this.tokenAuthorizationMiddleware = this.tokenAuthorizationMiddleware.bind(this)
		this.clientAuthorizationMiddleware = this.clientAuthorizationMiddleware.bind(this)
		this.clientAuthorization = this.clientAuthorization.bind(this)
		this.tokenAuthorization = this.tokenAuthorization.bind(this)

		this.init()
	}

	async init() {
		const url = process.env.MONGO_URL
		this.client = await MongoClient.connect(url, { 
			useNewUrlParser: true,
			useUnifiedTopology: true
		})
	}

	async clientAuthorization(payload) {
		try {
			// check if payload.clientId && payload.clientSecret match in database
			const data = await this.client.db('auth').collection('clients').findOne({
				clientId: payload.clientId,
				clientSecret: payload.clientSecret
			})

			if(!data) {
				throw ({
					message: 'invalid client credential'
				})				
			}

			return {
				status: 'success',
				data: {}
			}	
		} catch (err) {
			const message = err.message || 'please try again'
			return {
				status: 'error',
				message: message
			}
		}
	}

	async tokenAuthorization(payload) {
		try {
			// check if jwt valid
			if(!payload.accessToken || payload.accessToken.length === 0) {
				throw ({
					message: 'invalid authorization format'
				})
			}

			const [head, token] = payload.accessToken.split(' ')
			if(head !== 'Bearer') {
				throw ({
					message: 'invalid authorization format'
				})
			}

			jwt.verify(token, this.secretKey)

			return {
				status: 'success',
				data: {}
			}
		} catch (err) {
			const message = err.message || 'please try again'
			return {
				status: 'error',
				message: message
			}
		}
	}

	async tokenAuthorizationMiddleware(req, res, next) {
		const payload = {
			accessToken: req.headers['authorization']
		}

		const response = await this.tokenAuthorization(payload)

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

		const response = await this.clientAuthorization(payload)

		if(response.status === 'success') {
			return next()
		}

		return res.json(response)
	}


	async confirmAuthentication(payload) {
		try {
			schemas.confirmAuthentication.validateSync(payload)	
			if(payload.type === 'register') {
				// decrypt and parse the payload
				const tokenJSONpayload = this.cryptr.decrypt(payload.token)
				const tokenPayload = JSON.parse(tokenJSONpayload)
	
				// throw error if payload expired
				if(new Date().getTime() > tokenPayload.expiresInTs) {
					throw ({
						message: 'expired token'
					})
				}
	
				// check if email already registered
				const user = await this.client.db('auth').collection('users').findOne({
					email: tokenPayload.email
				})
	
				// throw error if email already registered
				if(user) {
					throw ({
						message: 'email already registered'
					})
				}
	
				// create new user based on payload
				await this.client.db('auth').collection('users').insertOne({
					uid: tokenPayload.uid,
					email: tokenPayload.email,
					password: tokenPayload.password,
					createdAt: new Date().toISOString()
				})
		
				// return success
				return {
					status: 'success',
					data: {}
				}
			}
			if(payload.type === 'login') {
				const data = await this.client.db('auth').collection('confirmations').findOne({
					token: payload.token
				})
				if(!data) {
					throw ({
						message: 'invalid token'
					})
				}
				if(data.expiresInTs < new Date().getTime()) {
					throw ({
						message: 'expired token'
					})
				}
				const tokenPayload = JSON.parse(data.payload)
		
				if(data.type === 'CONFIRM_LOGIN') {
					await this.client.db('auth').collection('tokens').findOneAndUpdate({
						refreshToken: tokenPayload.refreshToken
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
		} catch (err) {
			let message = err.message || 'please try again'
			if(err.message === 'Invalid IV length') {
				message = 'invalid token'
			}
			return {
				status: 'error',
				message: message
			}	
		}
	}

	async authentication(payload) {
		let userUid = null
		let userEmail = null

		if(payload.type === 'refreshToken') {
			try {
				schemas.refreshTokenAuthentication.validateSync(payload)
			} catch (err) {
				return {
					status: 'error',
					message: 'invalid parameters',
					errors: err.errors
				}
			}
			// check token in database
			const token = await this.client.db('auth').collection('tokens').findOne({
				refreshToken: payload.refreshToken
			})
			
			// reject if token is not exist
			if(!token) {
				return {
					status: 'error',
					message: 'invalid token'
				}
			}
			// reject if token is inactive
			if(token.status === 'inactive') {
				return {
					status: 'error',
					message: 'inactive token'
				}
			}
			// reject if token is expired
			if(token.status === 'expired') {
				return {
					status: 'error',
					message: 'expired token'
				}
			}
			// update token status if it's already expired
			if(token.refreshTokenExpiresInTs < new Date().getTime()) {
				await this.client.db('auth').collection('tokens').findOneAndUpdate({
					refreshToken: payload.refreshToken
				}, {
					$set: {
						status: 'expired'
					}
				})

				return {
					status: 'error',
					message: 'expired token'
				}
			}

			userUid = token.userUid
		}
		else if(payload.type === 'password') {
			try {
				schemas.passwordAuthentication.validateSync(payload)
			} catch (err) {
				return {
					status: 'error',
					message: 'invalid parameters',
					errors: err.errors
				}
			}
			// reject if payload.email && payload.password is not match
			const user = await this.client.db('auth').collection('users').findOne({
				email: payload.email
			})
			if(!user) {
				return {
					status: 'error',
					message: 'invalid email or password'
				}
			}

			const passwordMatch = bcrypt.compareSync(payload.password, user.password)
			if(!passwordMatch) {
				return {
					status: 'error',
					message: 'invalid email or password'
				}
			}

			userUid = user.uid
			userEmail = user.email
		}
		else {
			return {
				status: 'error',
				message: 'invalid authentication type'
			}
		}

		// generate access token & refresh token
		const refreshToken = uuidv4()
		const accessToken = jwt.sign({
			userUid: userUid,
			exp: (new Date().getTime() + this.accessTokenLifetime) / 1000
		}, this.secretKey)
		const status = payload.type === 'refreshToken' ? 'active' : 'inactive'

		const response = await this.client.db('auth').collection('tokens').insertOne({
			userUid: userUid,
			accessToken: accessToken,
			expiresInTs: new Date().getTime() + this.accessTokenLifetime,
			refreshToken: refreshToken,
			refreshTokenExpiresInTs: new Date().getTime() + this.refreshTokenLifetime,
			status: status,
			createdAt: new Date().toISOString()
		})

		const responseData = response.ops[0]

		// only send refreshToken for type password
		if(payload.type === 'password') {
			delete responseData.accessToken
			delete responseData.expiresInTs

			// 2FA email
			const confToken = uuidv4()
			await this.client.db('auth').collection('confirmations').insertOne({
				token: confToken,
				userUid: userUid,
				type: 'CONFIRM_LOGIN',
				payload: JSON.stringify({
					refreshToken: refreshToken
				}),
				expiresInTs: new Date().getTime() + (15 * 60 * 1000),
				createdAt: new Date().toISOString()
			})

			// send email with confUid
			mail.send({
				from: `no-reply@vestrade.io`,
				to: userEmail,
				subject: `Login Confirmation`,
				html: `hello here's your token ${confToken}`
			})
		}

		return {
			status: 'success',
			data: responseData
		}
	}

	async revokeToken(payload) {
		try {
			schemas.revokeToken.validateSync(payload)
			if(payload.type === 'refreshToken') {
				await this.client.db('auth').collection('tokens').findOneAndUpdate({
					refreshToken: payload.token
				}, {
					$set: {
						status: 'expired'
					}
				})
			}

			return {
				status: 'success',
				data: {}
			}
		} catch (err) {
			const message = err.message || 'please try again'
			const errors = err.errors || []
			return {
				status: 'error',
				message: message,
				errors: errors
			}
		}
	}

	async register(payload) {
		try {
			// validate input
			schemas.register.validateSync(payload, {
				abortEarly: false
			})

			// check if email exist
			const user = await this.client.db('auth').collection('users').findOne({
				email: payload.email
			})

			// throw error if email already registered
			if(user) {
				return {
					status: 'error',
					message: 'email already registered'
				}
			}

			// hash password
			const hashedPassword = bcrypt.hashSync(payload.password, this.salt)

			// generate uuid
			const uid = uuidv4()
			
			// encrypt data
			const encryptedData = this.cryptr.encrypt(JSON.stringify({
				uid: uid,
				email: payload.email,
				password: hashedPassword,
				expiresInTs: new Date().getTime() + ms('24h')
			}))

			// send email with encrypted data for verification
			mail.send({
				from: `no-reply@vestrade.io`,
				to: payload.email,
				subject: `Register Verification`,
				html: `hello here's your token ${encryptedData}`
			})

			// return success
			return {
				status: 'success',
				data: {}
			}	
		} catch (err) {
			const message = err.message || 'please try again'
			const errors = err.errors || []
			return {
				status: 'error',
				message: message,
				errors: errors
			}	
		}
	}
}