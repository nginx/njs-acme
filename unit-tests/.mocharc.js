'use strict'

process.env.BABEL_ENV = 'mocha'

module.exports = {
  checkLeaks: true,
  extension: ['ts'],
  require: [
    'babel-register-ts',
    'source-map-support/register',
  ],
  spec: [
    'unit-tests/**/*.test.ts',
  ],
}
