/**
 * ADDITIONAL EXAMPLES - Not required for the baseline implementation in
 * `index.ts` but may be interesting to people who want to create their own
 * implementations that may facilitate account creation or CSR generation.
 */

import { HttpClient } from './api'
import { LogLevel, Logger } from './logger'
import {
  acmeAccountPrivateJWKPath,
  acmeDirectoryURI,
  acmeVerifyProviderHTTPS,
  createCsr,
  generateKey,
  readOrCreateAccountKey,
  toPEM,
} from './utils'
import { AcmeClient } from './client'

const log = new Logger()

/**
 * Demonstrates how to use generate RSA Keys and use HttpClient
 * @param r
 * @returns
 */
async function acmeNewAccount(r: NginxHTTPRequest): Promise<void> {
  // Generate a new RSA key pair for ACME account
  const keys = (await generateKey()) as Required<CryptoKeyPair>

  // Create a new ACME account
  const client = new HttpClient(acmeDirectoryURI(r), keys.privateKey)

  client.minLevel = LogLevel.Debug
  client.setVerify(acmeVerifyProviderHTTPS(r))

  // Get Terms Of Service link from the ACME provider
  const tos = await client.getMetaField('termsOfService')
  log.info(`termsOfService: ${tos}`)
  // obtain a resource URL
  const resourceUrl: string = await client.getResourceUrl('newAccount')
  const payload = {
    termsOfServiceAgreed: true,
    contact: ['mailto:test@example.com'],
  }
  // Send a signed request
  const sresp = await client.signedRequest(resourceUrl, payload)

  const respO = {
    headers: sresp.headers,
    data: await sresp.json(),
    status: sresp.status,
  }
  return r.return(200, JSON.stringify(respO))
}

/**
 * Using AcmeClient to create a new account. It creates an account key if it doesn't exist
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientNewAccount(r: NginxHTTPRequest): Promise<void> {
  const accountKey = await readOrCreateAccountKey(acmeAccountPrivateJWKPath(r))
  // Create a new ACME account
  const client = new AcmeClient({
    directoryUrl: acmeDirectoryURI(r),
    accountKey: accountKey,
  })
  // display more logs
  client.api.minLevel = LogLevel.Debug
  // conditionally validate ACME provider cert
  client.api.setVerify(acmeVerifyProviderHTTPS(r))

  try {
    const account = await client.createAccount({
      termsOfServiceAgreed: true,
      contact: ['mailto:test@example.com'],
    })
    return r.return(200, JSON.stringify(account))
  } catch (e) {
    const errMsg = `Error creating ACME account. Error=${e}`
    log.error(errMsg)
    return r.return(500, errMsg)
  }
}

/**
 * Create a new certificate Signing Request - Example implementation
 * @param r
 * @returns
 */
async function createCsrHandler(r: NginxHTTPRequest): Promise<void> {
  const { pkcs10Ber, keys } = await createCsr({
    // EXAMPLE VALUES BELOW
    altNames: ['proxy1.f5.com', 'proxy2.f5.com'],
    commonName: 'proxy.f5.com',
    state: 'WA',
    country: 'US',
    organizationUnit: 'NGINX',
  })
  const privkey = (await crypto.subtle.exportKey(
    'pkcs8',
    keys.privateKey
  )) as ArrayBuffer
  const pubkey = (await crypto.subtle.exportKey(
    'spki',
    keys.publicKey
  )) as ArrayBuffer
  const privkeyPem = toPEM(privkey, 'PRIVATE KEY')
  const pubkeyPem = toPEM(pubkey, 'PUBLIC KEY')
  const csrPem = toPEM(pkcs10Ber, 'CERTIFICATE REQUEST')
  const result = `${privkeyPem}\n${pubkeyPem}\n${csrPem}`
  return r.return(200, result)
}

export default {
  acmeNewAccount,
  clientNewAccount,
  createCsrHandler,
}
