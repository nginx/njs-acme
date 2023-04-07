'use strict'

process.env.BABEL_ENV = 'mocha'

module.exports = {
  checkLeaks: true,
  extension: ['ts'],
  require: [
    "ts-node/register"
    //     // 'babel-register-ts',
    //     // 'source-map-support/register',
    //     // 'tests/hooks.ts',
  ],
  spec: [
    'tests/**/*.test.ts',
  ],
}
