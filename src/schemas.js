const yup = require('yup')

module.exports = {
  register: yup.object().shape({
    email: yup.string().email().required(),
    password: yup.string().required()
  }),

  registerConfirmation: yup.object().shape({
    encryptedData: yup.string().required()
  }),

  passwordAuthentication: yup.object().shape({
    type: yup.string().matches(/password/).required(),
    email: yup.string().email().required(),
    password: yup.string().required()
  }),

  refreshTokenAuthentication: yup.object().shape({
    type: yup.string().matches(/refreshToken/).required(),
    refreshToken: yup.string().required(),
  })
}