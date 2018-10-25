const jwt = require('jsonwebtoken')
const isEmpty = require('./LangUtils')
const env = require('../../env')

const authenticate = token => {
  try {
    if (!token || isEmpty(token)) {
      return { error: 'JWT required', status: 401 }
    }
    const verify = jwt.verify(token, env.JWT_KEY)

    const { exp } = verify
    if (exp * 1000 < Date.now()) {
      return { error: 'JWT expired', status: 401 }
    }

    return true
  } catch (error) {
    console.error(error) // eslint-disable-line no-console

    return { error: 'unknown error', status: 500 }
  }
}

module.exports = authenticate
