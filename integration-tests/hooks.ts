// import * as FS from 'fs'
import got, { Got } from 'got'
import { Context, RootHookObject } from 'mocha'
import { beforeEachSuite } from 'mocha-suite-hooks'
import { startNginx, NginxServer } from 'nginx-testing'

const nginxConfig = `${__dirname}/nginx.conf`
const nginxVersion = process.env.NGINX_VERSION || '1.22.x'
const host = '127.0.0.1'

declare module 'mocha' {
    export interface Context {
        client: Got
        nginx: NginxServer
    }
}


export const mochaHooks: RootHookObject = {
    async beforeAll(this: Context) {
        this.timeout(30_000)

        this.nginx = await startNginx({ version: nginxVersion, bindAddress: host, configPath: nginxConfig })

        const errors = (await this.nginx.readErrorLog())
            .split('\n')
            .filter(line => line.includes('[error]'))
        if (errors) {
            console.error(errors.join('\n'))
        }

        this.client = got.extend({
            prefixUrl: `http://${host}:${this.nginx.port}`,
            throwHttpErrors: false,
        })

        beforeEachSuite(async function () {
            // Read the logs to consume (discard) them before running next test suite
            // (describe block).
            await this.nginx.readErrorLog()
            await this.nginx.readAccessLog()
        })
    },

    async afterAll(this: Context) {
        if (this.nginx) {
            await this.nginx.stop()
        }
    },

    async afterEach(this: Context) {
        const { currentTest, nginx } = this

        if (currentTest?.state === 'failed' && currentTest.err) {
            const errorLog = await nginx.readErrorLog()
            const accessLog = await nginx.readAccessLog()

            const logs = [
                errorLog && '----- Error Log -----\n' + errorLog,
                accessLog && '----- Access Log -----\n' + accessLog,
            ].filter(Boolean)

            if (logs.length > 0) {
                currentTest.err.stack += '\n\n' + logs.join('\n\n').replace(/^/gm, '    ')
            }
        }
    }
}
