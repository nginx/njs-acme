import {
  acmeAccountPrivateJWKPath,
  acmeAltNames,
  acmeChallengeDir,
  acmeCommonName,
  acmeDir,
  acmeDirectoryURI,
  acmeServerNames,
  acmeVerifyProviderHTTPS,
  areEqualSets,
  createCsr,
  getVariable,
  joinPaths,
  readCertificateInfo,
  readOrCreateAccountKey,
  readCert,
  readKey,
  toPEM,
  KEY_SUFFIX,
  CERTIFICATE_SUFFIX,
  CERTIFICATE_REQ_SUFFIX,
  purgeCachedCertKey,
} from './utils'
import { AcmeClient } from './client'
import fs from 'fs'
import { LogLevel, Logger } from './logger'

// TODO: make this configurable
const RENEWAL_THRESHOLD_DAYS = 30

const log = new Logger()

async function clientAutoMode(r: NginxPeriodicSession): Promise<boolean> {
  const result = await clientAutoModeInternal(r)
  if (!result.success) {
    log.error(
      `clientAutoModeInternal returned an error: ${JSON.stringify(result.info)}`
    )
  }
  return result.success
}

type clientAutoModeReturnType = {
  success: boolean
  info: Record<string, unknown>
}

/**
 *  Method to use if you want to be able to trigger a certificate refresh from an HTTP request.
 *
 *
 * @param {NginxHTTPRequest} r Incoming session or request
 * @returns void
 */
async function clientAutoModeHTTP(r: NginxHTTPRequest): Promise<void> {
  try {
    const result = await clientAutoModeInternal(r)
    if (!result.success) {
      log.error(
        `clientAutoModeInternal returned an error: ${JSON.stringify(
          result.info
        )}`
      )
    }
    return r.return(result.success ? 200 : 500, JSON.stringify(result.info))
  } catch (e) {
    log.error('ERROR: ' + JSON.stringify(e))
    return r.return(500, JSON.stringify({ error: e }))
  }
}

/**
 *  An automated workflow to issue a new certificate for `njs_acme_server_names`
 *
 * @param {NginxPeriodicSession | NginxHTTPRequest} r Incoming session or request
 * @returns ClientAutoModeReturnType
 */
async function clientAutoModeInternal(
  r: NginxPeriodicSession | NginxHTTPRequest
): Promise<clientAutoModeReturnType> {
  const log = new Logger('auto')
  const prefix = acmeDir(r)
  const commonName = acmeCommonName(r)
  const altNames = acmeAltNames(r)
  const retVal: clientAutoModeReturnType = {
    success: false,
    info: {},
  }

  const pkeyPath = joinPaths(prefix, commonName + KEY_SUFFIX)
  const csrPath = joinPaths(prefix, commonName + CERTIFICATE_REQ_SUFFIX)
  const certPath = joinPaths(prefix, commonName + CERTIFICATE_SUFFIX)

  let email
  try {
    email = getVariable(r, 'njs_acme_account_email')
  } catch {
    retVal.info.error =
      "Nginx variable '$njs_acme_account_email' or 'NJS_ACME_ACCOUNT_EMAIL' environment variable must be set"
    return retVal
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
      retVal.info.error = `Error creating directory to store challenges. Ensure the ${challengePath} directory is writable by the nginx user.`
      return retVal
    }

    certificatePem = await client.auto({
      csr: Buffer.from(csr.pkcs10Ber),
      email,
      termsOfServiceAgreed: true,
      challengeCreateFn: async (_, challenge, keyAuthorization) => {
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

    // Purge the cert/key in the shared dict zone if applicable
    purgeCachedCertKey(r)
  }

  retVal.success = true
  retVal.info.certificate = certInfo
  retVal.info.renewedCertificate = renewCertificate.toString()

  return retVal
}

/**
 * Retrieves the cert based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string, string} - The path and cert associated with the server name.
 */
function js_cert(r: NginxHTTPRequest): string {
  return readCert(r)
}

/**
 * Retrieves the key based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The path and key associated with the server name.
 */
function js_key(r: NginxHTTPRequest): string {
  return readKey(r)
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

export default {
  js_cert,
  js_key,
  challengeResponse,
  clientAutoModeHTTP,
  clientAutoMode,
  LogLevel,
}
