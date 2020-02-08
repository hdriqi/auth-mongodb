const yup = require('yup')

module.exports = {
  register: yup.object().shape({
    email: yup.string().email().required(),
    password: yup.string().required()
  }),

  confirmAuthentication: yup.object().shape({
    type: yup.string().matches(/(register|login)/, {
      message: 'type must be either register or login'
    }).required(),
    token: yup.string().required()
  }),

  requestResetPassword: yup.object().shape({
    email: yup.string().email().required()
  }),

  confirmResetPassword: yup.object().shape({
    token: yup.string().required(),
    password: yup.string().required()
  }),

  revokeToken: yup.object().shape({
    type: yup.string().matches(/(refreshToken)/, {
      message: 'type must be refreshToken'
    }).required(),
    token: yup.string().required()
  }),

  passwordAuthentication: yup.object().shape({
    type: yup.string().matches(/password/, {
      message: 'type must be password'
    }).required(),
    email: yup.string().email().required(),
    password: yup.string().required()
  }),

  refreshTokenAuthentication: yup.object().shape({
    type: yup.string().matches(/refreshToken/, {
      message: 'type must be refreshToken'
    }).required(),
    refreshToken: yup.string().required(),
  })
}