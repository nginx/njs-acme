// import * as FS from 'fs'
import got, { Got } from 'got'
import { Context, RootHookObject } from 'mocha'
import { beforeEachSuite } from 'mocha-suite-hooks'
import { startNginx, NginxServer, NginxOptions } from 'nginx-testing'

const nginxConfig = `${__dirname}/nginx.conf`
// use specified "local" already insatlled nginx (e.g. /usr/sbin/nginx)
// instead of pulling nginx binary from nginx-testing lib
const useNginxBinPath = process.env.USE_NGINX_BIN_PATH
// let nginx-testing to know which nginx to download (not official builds)
const nginxVersion = process.env.NGINX_VERSION || '1.25.x'
//
export const host = process.env.NGINX_HOSTNAME || '127.0.0.1'

declare module 'mocha' {
  export interface Context {
    client: Got
    nginx: NginxServer
    nginxHost: string
  }
}

export const mochaHooks: RootHookObject = {
  async beforeAll(this: Context) {
    this.timeout(30_000)
    this.nginxHost = host

    const opts = {
      bindAddress: this.nginxHost,
      configPath: nginxConfig,
      ports: [8000, 4443],
      workDir: __dirname,
    } as NginxOptions

    if (useNginxBinPath) {
      opts.binPath = useNginxBinPath
    } else {
      opts.version = nginxVersion
    }
    console.info('running tests in folder', process.cwd())
    console.info('using opts', opts)
    this.nginx = await startNginx(opts)
    console.info('nginx config\n', this.nginx.config)

    const errors = (await this.nginx.readErrorLog())
      .split('\n')
      .filter((line) => line.includes('[error]'))
    if (errors) {
      console.error(errors.join('\n'))
    }

    this.client = got.extend({
      prefixUrl: `http://${this.nginxHost}:${this.nginx.port}`,
      throwHttpErrors: false,
    })

    beforeEachSuite(async function () {
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
        currentTest.err.stack +=
          '\n\n' + logs.join('\n\n').replace(/^/gm, '    ')
      }
    }
  },
}
