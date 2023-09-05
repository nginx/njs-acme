import {
  acmeAccountPrivateJWKPath,
  acmeAltNames,
  acmeChallengeDir,
  acmeClientAutoModeURL,
  acmeCommonName,
  acmeDir,
  acmeDirectoryURI,
  acmeServerNames,
  acmeVerifyProviderHTTPS,
  acmeZoneName,
  areEqualSets,
  createCsr,
  generateKey,
  getVariable,
  joinPaths,
  readCertificateInfo,
  readOrCreateAccountKey,
  toPEM,
} from './utils'
import { HttpClient } from './api'
import { AcmeClient } from './client'
import fs from 'fs'
import { LogLevel, Logger } from './logger'

const KEY_SUFFIX = '.key'
const CERTIFICATE_SUFFIX = '.crt'
const CERTIFICATE_REQ_SUFFIX = '.csr'
const RENEWAL_THRESHOLD_DAYS = 30

const log = new Logger()

/**
 *  Demonstrates an automated workflow to issue a new certificate for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest): Promise<boolean> {
  const log = new Logger('auto')
  const prefix = acmeDir(r)
  const commonName = acmeCommonName(r)
  const altNames = acmeAltNames(r)

  const pkeyPath = joinPaths(prefix, commonName + KEY_SUFFIX)
  const csrPath = joinPaths(prefix, commonName + CERTIFICATE_REQ_SUFFIX)
  const certPath = joinPaths(prefix, commonName + CERTIFICATE_SUFFIX)

  let email
  try {
    email = getVariable(r, 'njs_acme_account_email')
  } catch {
    log.error(
      "Nginx variable '$njs_acme_account_email' or 'NJS_ACME_ACCOUNT_EMAIL' environment variable must be set"
    )
    return false
  }

  let certificatePem
  let pkeyPem
  let renewCertificate = false
  let certInfo
  try {
    const certData = fs.readFileSync(certPath, 'utf8')
    const privateKeyData = fs.readFileSync(pkeyPath, 'utf8')

    certInfo = await readCertificateInfo(certData)

    const configDomains = acmeServerNames(r)
    const certDomains = certInfo.domains.altNames // altNames includes the common name

    if (!areEqualSets(certDomains, configDomains)) {
      log.info(
        `Renewing certificate because the hostnames in the certificate (${certDomains.join(
          ', '
        )}) do not match the configured njs_acme_server_names (${configDomains.join(
          ','
        )})`
      )
      renewCertificate = true
    } else {
      // Calculate the date RENEWAL_THRESHOLD_DAYS before the certificate expiration
      const renewalThreshold = new Date(certInfo.notAfter)
      renewalThreshold.setDate(
        renewalThreshold.getDate() - RENEWAL_THRESHOLD_DAYS
      )

      const currentDate = new Date()
      if (currentDate > renewalThreshold) {
        log.info(
          `Renewing certificate because the current certificate expires within the renewal threshold of ${RENEWAL_THRESHOLD_DAYS} days.`
        )
        renewCertificate = true
      } else {
        certificatePem = certData
        pkeyPem = privateKeyData
      }
    }
  } catch {
    renewCertificate = true
  }

  log.info(`in clientAutoMode renew=${renewCertificate}`)

  if (renewCertificate) {
    const accountKey = await readOrCreateAccountKey(
      acmeAccountPrivateJWKPath(r)
    )
    // Create a new ACME client
    const client = new AcmeClient({
      directoryUrl: acmeDirectoryURI(r),
      accountKey: accountKey,
    })
    client.api.setVerify(acmeVerifyProviderHTTPS(r))

    // Create a new CSR
    const csr = await createCsr({
      commonName,
      altNames,
      emailAddress: email,
    })
    fs.writeFileSync(csrPath, toPEM(csr.pkcs10Ber, 'CERTIFICATE REQUEST'))

    const privKey = (await crypto.subtle.exportKey(
      'pkcs8',
      csr.keys.privateKey
    )) as ArrayBuffer
    pkeyPem = toPEM(privKey, 'PRIVATE KEY')
    fs.writeFileSync(pkeyPath, pkeyPem)
    log.info(`Wrote private key to ${pkeyPath}`)

    const challengePath = acmeChallengeDir(r)

    try {
      fs.mkdirSync(challengePath, { recursive: true })
    } catch (e) {
      log.error(
        `Error creating directory to store challenges. Ensure the ${challengePath} directory is writable by the nginx user.`
      )
      return false
    }

    certificatePem = await client.auto({
      csr: Buffer.from(csr.pkcs10Ber),
      email,
      termsOfServiceAgreed: true,
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        log.info('Challenge Create', { authz, challenge, keyAuthorization })
        log.info(
          `Writing challenge file so nginx can serve it via .well-known/acme-challenge/${challenge.token}`
        )
        const path = joinPaths(challengePath, challenge.token)
        fs.writeFileSync(path, keyAuthorization)
      },
      challengeRemoveFn: async (_authz, challenge, _keyAuthorization) => {
        const path = joinPaths(challengePath, challenge.token)
        try {
          fs.unlinkSync(path)
          log.info(`Removed challenge ${path}`)
        } catch (e) {
          log.error(`Failed to remove challenge ${path}`)
        }
      },
    })
    certInfo = await readCertificateInfo(certificatePem)
    fs.writeFileSync(certPath, certificatePem)
    log.info(`Wrote certificate to ${certPath}`)
  }

  return true
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

/**
 * Retrieves the cert based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string, string} - The path and cert associated with the server name.
 */
function js_cert(r: NginxHTTPRequest): string {
  return read_cert_or_key(r, CERTIFICATE_SUFFIX)
}

/**
 * Retrieves the key based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The path and key associated with the server name.
 */
function js_key(r: NginxHTTPRequest): string {
  return read_cert_or_key(r, KEY_SUFFIX)
}

/**
 * Given a request and suffix that indicates whether the caller wants the cert
 * or key, return the requested object from cache if possible, falling back to
 * disk.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @param {string} suffix - The file suffix that indicates whether we want a cert or key
 * @returns
 */
function read_cert_or_key(
  r: NginxHTTPRequest,
  suffix: typeof CERTIFICATE_SUFFIX | typeof KEY_SUFFIX
) {
  let data = ''
  const prefix = acmeDir(r)
  const commonName = acmeCommonName(r)
  const zone = acmeZoneName(r)
  const path = joinPaths(prefix, commonName + suffix)
  const key = ['acme', path].join(':')

  // if the zone is not defined in nginx.conf, then we will bypass the cache
  const cache = zone && ngx.shared && ngx.shared[zone]

  if (cache) {
    data = (cache.get(key) as string) || ''
    if (data) {
      return data
    }
  }
  try {
    data = fs.readFileSync(path, 'utf8')
  } catch (e) {
    log.error('error reading from file:', path, `. Error=${e}`)
    return ''
  }
  if (cache && data) {
    try {
      cache.set(key, data)
      log.debug(`wrote to cache: ${key} zone: ${zone}`)
    } catch (e) {
      const errMsg = `error writing to shared dict zone: ${zone}. Error=${e}`
      log.error(errMsg)
    }
  }
  return data
}

/**
 * Demonstrates using js_content to serve challenge responses.
 * @param {NginxHTTPRequest} the request
 */
async function challengeResponse(r: NginxHTTPRequest): Promise<void> {
  const challengeUriPrefix = '/.well-known/acme-challenge/'

  // Only support GET requests
  if (r.method !== 'GET') {
    return r.return(400, 'Bad Request')
  }

  // Here is the challenge token spec:
  // https://datatracker.ietf.org/doc/html/draft-ietf-acme-acme-07#section-8.3
  // - greater than 128 bits or ~22 base-64 encoded characters.
  //   Let's Encrypt uses a 43-character string.
  // - base64url character set only

  // Ensure we're not given a token that is too long (128 chars to be future-proof)
  if (r.uri.length > 128 + challengeUriPrefix.length) {
    return r.return(400, 'Bad Request')
  }

  // Ensure this handler is only receiving /.well-known/acme-challenge/
  // requests, and not other requests through some kind of configuration
  // mistake.
  if (!r.uri.startsWith(challengeUriPrefix)) {
    return r.return(400, 'Bad Request')
  }

  const token = r.uri.substring(challengeUriPrefix.length)

  // Token must only contain base64url chars
  if (token.match(/[^a-zA-Z0-9-_]/)) {
    return r.return(400, 'Bad Request')
  }

  try {
    return r.return(
      200,
      // just return the contents of the token file
      fs.readFileSync(joinPaths(acmeChallengeDir(r), token), 'utf8')
    )
  } catch (e) {
    return r.return(404, 'Not Found')
  }
}

/*
 * Handler for the `js_periodic` directive that requests /acme/auto periodically
 * to validate the stored certitificates.
 */
async function periodicAuto(): Promise<void> {
  // make the /acme/auto request to localhost
  await ngx.fetch(acmeClientAutoModeURL())
}

export default {
  js_cert,
  js_key,
  acmeNewAccount,
  challengeResponse,
  clientNewAccount,
  clientAutoMode,
  createCsrHandler,
  LogLevel,
  Logger,
  periodicAuto,
}
