import { webcrypto } from 'crypto'

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

const globalAny: Record<string, unknown> = global
globalAny.ngx = new FakeNGX()

/* node 19 and later expose webcrypto as a read-only global already */
if (!globalAny.crypto) {
  globalAny.crypto = webcrypto
}
