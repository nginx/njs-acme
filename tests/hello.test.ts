import { strict as assert } from 'assert'
import { after, afterEach, before, beforeEach, test } from 'mocha'
import { startNginx, NginxServer } from 'nginx-testing'
import fetch from 'node-fetch'

let nginx: NginxServer

before(async () => {
  nginx = await startNginx({ version: '1.18.x', configPath: './nginx.conf' })
})

after(async () => {
  await nginx.stop()
})

beforeEach(async () => {
  // Consume logs (i.e. clean them before the test).
  await nginx.readAccessLog()
  await nginx.readErrorLog()
})

afterEach(async function () {
  // Print logs if the test failed.
  if (this.currentTest?.state === 'failed') {
    console.error('Access log:\n' + await nginx.readAccessLog())
    console.error('Error log:\n' + await nginx.readErrorLog())
  }
})

test('GET / results in HTTP 200', async () => {
  const resp = await fetch(`http://localhost:${nginx.port}/`)
  assert.equal(resp.status, 200)
})
