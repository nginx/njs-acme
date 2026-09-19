import assert from 'assert'
import { describe, it } from 'mocha'
import * as pkijs from 'pkijs'
import {
  acmeServerNames,
  createCsr,
  generateKey,
  isValidHostname,
} from '../src/utils'

/** ecdsa-with-SHA256 */
const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2'
/** sha256WithRSAEncryption */
const SHA256_WITH_RSA = '1.2.840.113549.1.1.11'

describe('utils', () => {
  describe('isValidHostname', () => {
    it('returns true for valid names', () => {
      assert(isValidHostname('nginx.com'))
      assert(isValidHostname('5guys.nginx.com'))
      assert(isValidHostname('5guys.nginx.com.'))
      assert(isValidHostname('5-guys.'))
      assert(isValidHostname('5'))
      assert(isValidHostname('a-z.123'))
      assert(isValidHostname('a.'.repeat(100)))
      assert(isValidHostname('a'.repeat(61) + '.com'))
    })
    it('returns false for invalid names', () => {
      assert(!isValidHostname('.com'))
      assert(!isValidHostname('.foobarbaz'))
      assert(!isValidHostname('*.nginx.com'))
      assert(!isValidHostname('-5guys.'))
      assert(!isValidHostname('5guys-'))
      assert(!isValidHostname('domäin.'))
      assert(!isValidHostname('  '))
      assert(!isValidHostname(''))
      assert(!isValidHostname('a'.repeat(65) + '.com'))
      assert(!isValidHostname('*'))
      assert(
        !isValidHostname(
          // too long - 256 chars
          '1234567890abcdef'.repeat(16)
        )
      )
    })
  })
  describe('acmeServerNames', () => {
    it('returns an array given valid input', () => {
      const r = {
        variables: {
          njs_acme_server_names: null,
        },
      } as unknown as NginxHTTPRequest
      const testCases = {
        'nginx.com': 1,
        'foo.bar.baz': 1,
        'foo.bar.baz foo.baz': 2,
        'foo. bar. baz.': 3,
        'foo.,bar.': 2,
        'foo.\tbar.': 2,
        'foo.        bar.': 2,
      }

      for (const [names, expected] of Object.entries(testCases)) {
        r.variables.njs_acme_server_names = names
        const result = acmeServerNames(r)
        assert(result.length === expected)
      }
    })
    it('throws given invalid input', () => {
      const r = {
        variables: {
          njs_acme_server_names: null,
        },
      } as unknown as NginxHTTPRequest
      for (const name of [
        'nginx-.com',
        '*.bar.baz',
        'foo.bar.baz *.baz',
        '-foo. bar. baz.',
      ]) {
        r.variables.njs_acme_server_names = name
        assert.throws(() => acmeServerNames(r))
      }
    })
  })
})

describe('createCsr', function () {
  /* RSA key generation is slow enough to trip the default 2s timeout */
  this.timeout(30000)

  const csrParams = {
    commonName: 'proxy.example.com',
    altNames: ['proxy2.example.com'],
  }

  const parseCsr = (pkcs10Ber: ArrayBuffer) =>
    pkijs.CertificationRequest.fromBER(pkcs10Ber)

  it('generates an RSA key pair by default', async () => {
    const { pkcs10Ber, keys } = await createCsr(csrParams)
    const pkcs10 = parseCsr(pkcs10Ber)

    assert.strictEqual(keys.privateKey.algorithm.name, 'RSASSA-PKCS1-v1_5')
    assert.strictEqual(pkcs10.signatureAlgorithm.algorithmId, SHA256_WITH_RSA)
    assert(await pkcs10.verify())
  })

  it('uses the key pair it is given', async () => {
    const keys = (await generateKey()) as Required<CryptoKeyPair>
    const { pkcs10Ber, keys: returnedKeys } = await createCsr({
      ...csrParams,
      keys,
    })

    assert.strictEqual(returnedKeys.privateKey, keys.privateKey)
    assert.strictEqual(returnedKeys.publicKey, keys.publicKey)

    /* the CSR carries the public key it was handed, not a freshly minted one */
    const spki = (await crypto.subtle.exportKey(
      'spki',
      keys.publicKey
    )) as ArrayBuffer
    const csrSpki = parseCsr(pkcs10Ber).subjectPublicKeyInfo.toSchema().toBER()
    assert.deepStrictEqual(Buffer.from(csrSpki), Buffer.from(spki))
    assert(await parseCsr(pkcs10Ber).verify())
  })

  it('generates a key of the requested size', async () => {
    const { keys } = await createCsr({ ...csrParams, keySize: 1024 })
    const alg = keys.privateKey.algorithm as RsaHashedKeyGenParams

    assert.strictEqual(alg.modulusLength, 1024)
  })

  it('signs with ECDSA when generating an EC key', async () => {
    const { pkcs10Ber, keys } = await createCsr({
      ...csrParams,
      keyAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    })
    const pkcs10 = parseCsr(pkcs10Ber)

    assert.strictEqual(keys.privateKey.algorithm.name, 'ECDSA')
    assert.strictEqual(pkcs10.signatureAlgorithm.algorithmId, ECDSA_WITH_SHA256)
    assert(await pkcs10.verify())
  })
})
