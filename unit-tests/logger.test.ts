import assert from 'assert'
import { describe, it } from 'mocha'
import { LogLevel, Logger } from '../src/logger'

describe('Logger', () => {
  it('adds a prefix', () => {
    const ngx = new FakeNGX()
    const log = new Logger('my-module', LogLevel.Info, ngx)

    log.info('message')

    assert.deepEqual(ngx.logs, [
      { level: ngx.INFO, message: 'njs-acme: [my-module] message' },
    ])
  })

  it("maps our four log levels to ngx's three log levels", () => {
    const ngx = new FakeNGX()
    const log = new Logger('t', LogLevel.Debug, ngx)

    log.debug('d')
    log.info('i')
    log.warn('w')
    log.error('e')

    assert.deepEqual(ngx.logs, [
      { level: ngx.INFO, message: 'njs-acme: [t] d' },
      { level: ngx.INFO, message: 'njs-acme: [t] i' },
      { level: ngx.WARN, message: 'njs-acme: [t] w' },
      { level: ngx.ERR, message: 'njs-acme: [t] e' },
    ])
  })

  it('omits logs below the minLevel', () => {
    const ngx = new FakeNGX()
    const log = new Logger('t', LogLevel.Info, ngx)

    log.debug('d')
    log.info('i')
    log.warn('w')
    log.error('e')

    assert.deepEqual(ngx.logs, [
      { level: ngx.INFO, message: 'njs-acme: [t] i' },
      { level: ngx.WARN, message: 'njs-acme: [t] w' },
      { level: ngx.ERR, message: 'njs-acme: [t] e' },
    ])
  })

  const testCases: Record<string, { args: unknown[]; expected: string }> = {
    'multiple args': {
      args: ['msg:', 4, true, 'another'],
      expected: 'msg: 4 true another',
    },
    objects: {
      args: ['did a thing:', { a: 1, b: 2 }],
      expected: 'did a thing: {"a":1,"b":2}',
    },
    'empty-ish args': {
      args: [null, '', undefined],
      expected: 'null  ',
    },
    arrays: {
      args: ['a:', [1, 2, 3]],
      expected: 'a: [1,2,3]',
    },
  }

  for (const [name, testCase] of Object.entries(testCases)) {
    it(`stringifies ${name}`, () => {
      const ngx = new FakeNGX()
      const log = new Logger('t', LogLevel.Info, ngx)

      log.info(...testCase.args)

      assert.deepEqual(ngx.logs, [
        { level: ngx.INFO, message: `njs-acme: [t] ${testCase.expected}` },
      ])
    })
  }
})

/**
 * Fake implementation of the logging functions of NGXObject
 */
class FakeNGX {
  readonly logs: { level: number; message: NjsStringOrBuffer }[]
  readonly INFO: number
  readonly WARN: number
  readonly ERR: number
  constructor() {
    this.logs = []
    this.INFO = 1
    this.WARN = 2
    this.ERR = 3
  }
  log(level: number, message: NjsStringOrBuffer) {
    this.logs.push({ level, message })
  }
}
