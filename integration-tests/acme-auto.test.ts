import { strict as assert } from 'assert'
import './hooks'

interface CertificateData {
  certificate: {
    issuer: {
      [key: string]: string
    }[]
    domains: {
      commonName: string
      altNames: string[][]
    }
    notBefore: string
    notAfter: string
  }
  renewedCertificate: boolean
}

describe('Integration:AutoMode', async function () {
  it('issue cert', async function () {
    this.timeout('10s')
    const resp = await this.client.get('')
    assert.equal(resp.statusCode, 200)
    const respBody = JSON.parse(resp.body)
    assert.equal(respBody.server_name, this.nginxHost)
    assert.equal(respBody.ssl_session_id, '')

    const respCert = await this.client.get('acme/auto')
    assert.equal(respCert.statusCode, 200)
    const certInfo = JSON.parse(respCert.body) as CertificateData
    assert(
      certInfo.certificate.domains.commonName.includes('Pebble Intermediate CA')
    )
    assert.equal(certInfo.certificate.domains.altNames.length, 1)
    assert.equal(certInfo.certificate.domains.altNames[0][0], this.nginxHost)

    const httpsClient = this.client.extend({
      prefixUrl: `https://${this.nginxHost}:${this.nginx.ports[1]}`,
      https: {
        rejectUnauthorized: false,
      },
    })

    const httpsResp = await httpsClient.get('')
    assert.equal(httpsResp.statusCode, 200)
    const httpsBody = JSON.parse(httpsResp.body)
    assert.equal(httpsBody.server_name, this.nginxHost)
    assert.notEqual(httpsBody.ssl_session_id, '')
  })
})
