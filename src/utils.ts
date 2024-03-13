import x509 from './x509.js'
import * as pkijs from 'pkijs'
import * as asn1js from 'asn1js'
import fs from 'fs'
import querystring from 'querystring'
import { ClientExternalAccountBindingOptions } from './client'
import { Logger } from './logger'

const log = new Logger('utils')

// workaround for PKI.JS to work
globalThis.unescape = querystring.unescape

// make PKI.JS to work with webcrypto
pkijs.setEngine(
  'webcrypto',
  new pkijs.CryptoEngine({ name: 'webcrypto', crypto: crypto })
)

export interface RsaPublicJwk {
  e: string
  kty: string
  n: string
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

export interface EcdsaPublicJwk {
  crv: string
  kty: string
  x: string
  y: string
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

const ACCOUNT_KEY_ALG_GENERATE: RsaHashedKeyGenParams = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
}

const ACCOUNT_KEY_ALG_IMPORT: RsaHashedImportParams = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
}

export const KEY_SUFFIX = '.key'
export const CERTIFICATE_SUFFIX = '.crt'
export const CERTIFICATE_REQ_SUFFIX = '.csr'

/**
 * Generates RSA private and public key pair
 * @returns {CryptoKeyPair} a private and public key pair
 */
export async function generateKey(): Promise<CryptoKey | CryptoKeyPair> {
  const keys = await crypto.subtle.generateKey(ACCOUNT_KEY_ALG_GENERATE, true, [
    'sign',
    'verify',
  ])
  return keys
}

/**
 * Reads the account key from the specified file path, or creates a new one if it does not exist.
 * @param {string} [path] - The path to the account key file. If not specified, the default location will be used.
 * @returns {Promise<CryptoKey>} - The account key as a CryptoKey object.
 * @throws {Error} - If the account key cannot be read or generated.
 */
export async function readOrCreateAccountKey(path: string): Promise<CryptoKey> {
  try {
    const accountKeyJWK = fs.readFileSync(path, 'utf8')
    log.info('Using account key from', path)
    return await crypto.subtle.importKey(
      'jwk',
      JSON.parse(accountKeyJWK),
      ACCOUNT_KEY_ALG_IMPORT,
      true,
      ['sign']
    )
  } catch (e) {
    // TODO: separate file not found, issues with importKey
    log.warn(`error ${e} while reading a private key from ${path}`)

    /* Generate a new RSA key pair for ACME account */
    const keys = (await generateKey()) as Required<CryptoKeyPair>
    const jwkFormated = await crypto.subtle.exportKey('jwk', keys.privateKey)
    fs.writeFileSync(path, JSON.stringify(jwkFormated))
    log.info('Generated a new account key and saved it to', path)
    return keys.privateKey
  }
}

interface JWK {
  crv: unknown
  x: unknown
  e: unknown
  y: unknown
  kty: unknown
  n: unknown
}
/**
 * Gets the public JWK from a given private key.
 * @param {CryptoKey} privateKey - The private key to extract the public JWK from.
 * @returns {Promise<RsaPublicJwk | EcdsaPublicJwk>} The public JWK.
 * @throws {Error} Throws an error if the privateKey parameter is not provided or invalid.
 */
export async function getPublicJwk(
  privateKey: CryptoKey
): Promise<RsaPublicJwk | EcdsaPublicJwk> {
  if (!privateKey) {
    const errMsg = 'Invalid or missing private key'
    log.error(errMsg)
    throw new Error(errMsg)
  }

  // eslint-disable-next-line @typescript-eslint/ban-types
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JWK

  if (jwk.crv && jwk.kty === 'EC') {
    const { crv, x, y, kty } = jwk
    return {
      crv,
      kty,
      x,
      y,
    } as EcdsaPublicJwk
  } else {
    return {
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    } as RsaPublicJwk
  }
}

/**
 * Add line break every 64th character
 * @param pemString {string}
 * @returns  {string}
 */
export function formatPEM(pemString: string): string {
  return pemString.replace(/(.{64})/g, '$1\n')
}

export type PemTag =
  | 'PRIVATE KEY'
  | 'PUBLIC KEY'
  | 'CERTIFICATE'
  | 'CERTIFICATE REQUEST'

/**
 * Convert ArrayBufferView | ArrayBuffer to PEM string
 * @param buffer The ArrayBufferView | ArrayBuffer to convert to PEM
 * @param tag The tag to use for the PEM header and footer
 * @returns The converted PEM string
 */
export function toPEM(
  buffer: string | Buffer | ArrayBufferView | ArrayBuffer,
  tag: PemTag
): string {
  /**
   * Convert the ArrayBufferView or ArrayBuffer to base64 and format it
   * as a PEM string
   */
  const pemBody = formatPEM(Buffer.from(buffer).toString('base64'))

  // Construct and return the final PEM string
  return [`-----BEGIN ${tag}-----`, pemBody, `-----END ${tag}-----`, ''].join(
    '\n'
  )
}

/**
 * Encodes a PKCS#10 certification request into an ASN.1 TBS (To-Be-Signed) sequence.
 *
 * @param pkcs10 The PKCS#10 certification request object to encode.
 * @returns An ASN.1 sequence object representing the TBS.
 */
export function encodeTBS(pkcs10: pkijs.CertificationRequest): asn1js.Sequence {
  const outputArray = [
    new asn1js.Integer({ value: pkcs10.version }),
    pkcs10.subject.toSchema(),
    pkcs10.subjectPublicKeyInfo.toSchema(),
  ]

  if (pkcs10.attributes !== undefined) {
    outputArray.push(
      new asn1js.Constructed({
        idBlock: {
          tagClass: 3, // CONTEXT-SPECIFIC
          tagNumber: 0, // [0]
        },
        value: Array.from(pkcs10.attributes, (o) => o.toSchema()),
      })
    )
  }

  return new asn1js.Sequence({
    value: outputArray,
  })
}

/**
 * Returns signature parameters based on the private key and hash algorithm
 *
 * @param privateKey {CryptoKey} The private key used for the signature
 * @param hashAlgorithm {string} The hash algorithm used for the signature. Default is "SHA-1".
 * @returns {{signatureAlgorithm: pkijs.AlgorithmIdentifier; parameters: pkijs.CryptoEngineAlgorithmParams;}} An object containing signature algorithm and parameters
 */
function getSignatureParameters(
  privateKey: CryptoKey,
  hashAlgorithm = 'SHA-1'
): {
  signatureAlgorithm: pkijs.AlgorithmIdentifier
  parameters: pkijs.CryptoEngineAlgorithmParams
} {
  // Check hashing algorithm
  pkijs.getOIDByAlgorithm({ name: hashAlgorithm }, true, 'hashAlgorithm')
  // Initial variables
  const signatureAlgorithm = new pkijs.AlgorithmIdentifier()

  //#region Get a "default parameters" for current algorithm
  const parameters = pkijs.getAlgorithmParameters(
    privateKey.algorithm.name,
    'sign'
  )
  if (!Object.keys(parameters.algorithm).length) {
    const errMsg = 'Parameter `algorithm` is empty'
    log.error(errMsg)
    throw new Error(errMsg)
  }
  const algorithm = parameters.algorithm
  algorithm.hash.name = hashAlgorithm
  //#endregion

  //#region Fill internal structures base on "privateKey" and "hashAlgorithm"
  switch (privateKey.algorithm.name.toUpperCase()) {
    case 'RSASSA-PKCS1-V1_5':
    case 'ECDSA':
      signatureAlgorithm.algorithmId = pkijs.getOIDByAlgorithm(algorithm, true)
      break
    case 'RSA-PSS':
      {
        //#region Set "saltLength" as a length (in octets) of hash function result
        switch (hashAlgorithm.toUpperCase()) {
          case 'SHA-256':
            algorithm.saltLength = 32
            break
          case 'SHA-384':
            algorithm.saltLength = 48
            break
          case 'SHA-512':
            algorithm.saltLength = 64
            break
          default:
        }
        //#endregion

        //#region Fill "RSASSA_PSS_params" object
        const paramsObject: Partial<pkijs.IRSASSAPSSParams> = {}

        if (hashAlgorithm.toUpperCase() !== 'SHA-1') {
          const hashAlgorithmOID = pkijs.getOIDByAlgorithm(
            { name: hashAlgorithm },
            true,
            'hashAlgorithm'
          )

          paramsObject.hashAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: hashAlgorithmOID,
            algorithmParams: new asn1js.Null(),
          })

          paramsObject.maskGenAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: '1.2.840.113549.1.1.8', // MGF1
            algorithmParams: paramsObject.hashAlgorithm.toSchema(),
          })
        }

        if (algorithm.saltLength !== 20)
          paramsObject.saltLength = algorithm.saltLength

        const pssParameters = new pkijs.RSASSAPSSParams(paramsObject)
        //#endregion

        //#region Automatically set signature algorithm
        signatureAlgorithm.algorithmId = '1.2.840.113549.1.1.10'
        signatureAlgorithm.algorithmParams = pssParameters.toSchema()
        //#endregion
      }
      break
    default:
      log.error(`Unsupported signature algorithm: ${privateKey.algorithm.name}`)
      throw new Error(
        `Unsupported signature algorithm: ${privateKey.algorithm.name}`
      )
  }
  //#endregion

  return {
    signatureAlgorithm,
    parameters,
  }
}

/**
 * Create a Certificate Signing Request
 *
 * @param {object} params - CSR parameters
 * @param {number} [params.keySize] - Size of the newly created private key, default: `2048`
 * @param {string} [params.commonName] - Common name
 * @param {string[]} [params.altNames] - Alternative names, default: `[]`
 * @param {string} [params.country] - Country name
 * @param {string} [params.state] - State or province name
 * @param {string} [params.locality] - Locality or city name
 * @param {string} [params.organization] - Organization name
 * @param {string} [params.organizationUnit] - Organization unit name
 * @param {string} [params.emailAddress] - Email address
 * @returns {Promise<{ pkcs10Ber: ArrayBuffer; keys: Required<CryptoKeyPair> }>} - Object containing
 * the PKCS10 BER representation and generated keys
 */
export async function createCsr(params: {
  keySize?: number
  commonName: string
  altNames: string[]
  country?: string
  state?: string
  locality?: string
  organization?: string
  organizationUnit?: string
  emailAddress?: string
}): Promise<{ pkcs10Ber: ArrayBuffer; keys: Required<CryptoKeyPair> }> {
  // TODO:  allow to provide keys in addition to always generating one
  const { privateKey, publicKey } =
    (await generateKey()) as Required<CryptoKeyPair>

  const pkcs10 = new pkijs.CertificationRequest()
  pkcs10.version = 0

  addSubjectAttributes(pkcs10.subject.typesAndValues, params)
  await addExtensions(pkcs10, params, publicKey)
  await signCsr(pkcs10, privateKey)

  const pkcs10Ber = getPkcs10Ber(pkcs10)

  return {
    pkcs10Ber,
    keys: { privateKey, publicKey },
  }
}

function addSubjectAttributes(
  subjectTypesAndValues: pkijs.AttributeTypeAndValue[],
  params: {
    country?: string
    state?: string
    organization?: string
    organizationUnit?: string
    commonName?: string
  }
): void {
  if (params.country) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue('2.5.4.6', params.country)
    )
  }
  if (params.state) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue('2.5.4.8', params.state)
    )
  }
  if (params.organization) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue('2.5.4.10', params.organization)
    )
  }
  if (params.organizationUnit) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue('2.5.4.11', params.organizationUnit)
    )
  }
  if (params.commonName) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue('2.5.4.3', params.commonName)
    )
  }
}

function createAttributeTypeAndValue(
  type: string,
  value: string
): pkijs.AttributeTypeAndValue {
  return new pkijs.AttributeTypeAndValue({
    type,
    value: new asn1js.Utf8String({ value }),
  })
}

function getServerNamesAsGeneralNames(params: {
  commonName?: string
  altNames?: string[]
}): pkijs.GeneralName[] {
  const altNames: pkijs.GeneralName[] = []

  // add common name first so that it becomes the cert common name
  if (
    params.commonName &&
    !altNames.some((name) => name.toString() === params.commonName)
  ) {
    altNames.push(createGeneralName(2, params.commonName))
  }

  // altNames follow common name
  if (params.altNames) {
    altNames.push(
      ...params.altNames.map((altName) => createGeneralName(2, altName))
    )
  }

  return altNames
}

function createGeneralName(
  type: 0 | 2 | 1 | 6 | 3 | 4 | 7 | 8 | undefined,
  value: string
): pkijs.GeneralName {
  return new pkijs.GeneralName({ type, value })
}

async function addExtensions(
  pkcs10: pkijs.CertificationRequest,
  params: { commonName: string; altNames: string[] },
  publicKey: CryptoKey
) {
  await pkcs10.subjectPublicKeyInfo.importKey(publicKey, pkijs.getCrypto(true))
  const subjectKeyIdentifier = await getSubjectKeyIdentifier(pkcs10)

  // Note that the set of AltNames must also include the commonName.
  const serverNamesGNs = new pkijs.GeneralNames({
    names: getServerNamesAsGeneralNames(params),
  })
  const extensions = new pkijs.Extensions({
    extensions: [
      createExtension('2.5.29.14', subjectKeyIdentifier), // SubjectKeyIdentifier
      createExtension('2.5.29.17', serverNamesGNs.toSchema()), // SubjectAltName
    ],
  })
  pkcs10.attributes = []
  pkcs10.attributes.push(
    new pkijs.Attribute({
      type: '1.2.840.113549.1.9.14', // pkcs-9-at-extensionRequest
      values: [extensions.toSchema()],
    })
  )
}

function createExtension(
  extnID: string,
  extnValue: asn1js.BaseBlock
): pkijs.Extension {
  return new pkijs.Extension({
    extnID,
    critical: false,
    extnValue: extnValue.toBER(false),
  })
}

async function getSubjectKeyIdentifier(
  pkcs10: pkijs.CertificationRequest
): Promise<asn1js.OctetString> {
  const subjectPublicKeyValue =
    pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex
  const subjectKeyIdentifier = await crypto.subtle.digest(
    'SHA-256',
    subjectPublicKeyValue
  )
  return new asn1js.OctetString({ valueHex: subjectKeyIdentifier })
}

async function signCsr(
  pkcs10: pkijs.CertificationRequest,
  privateKey: CryptoKey
): Promise<void> {
  /* Set signatureValue  */
  pkcs10.tbsView = new Uint8Array(encodeTBS(pkcs10).toBER())
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    pkcs10.tbsView
  )
  pkcs10.signatureValue = new asn1js.BitString({ valueHex: signature })

  /* Set signatureAlgorithm */
  const signatureParams = getSignatureParameters(privateKey, 'SHA-256')
  pkcs10.signatureAlgorithm = signatureParams.signatureAlgorithm
}

function getPkcs10Ber(pkcs10: pkijs.CertificationRequest): ArrayBuffer {
  return pkcs10.toSchema(true).toBER(false)
}

/**
 * Returns the Base64url encoded representation of the input data.
 *
 * @param {string} data - The data to be encoded.
 * @returns {string} - The Base64url encoded representation of the input data.
 */
export function getPemBodyAsB64u(data: string | Buffer): string {
  let buf = data
  if (typeof data === 'string') {
    buf = Buffer.from(data)
  }
  return buf.toString('base64url')
}

/**
 * Find and format error in response object
 *
 * @param {object} resp HTTP response
 * @returns {string} Error message
 */
// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any
export function formatResponseError(data: any): string {
  let result
  // const data = await resp.json();
  if ('error' in data) {
    result = data.error.detail || data.error
  } else {
    result = data.detail || JSON.stringify(data)
  }

  return result.replace(/\n/g, '')
}

/**
 * Exponential backoff
 *
 * https://github.com/mokesmokes/backo
 *
 * @class
 * @param {object} [opts]
 * @param {number} [opts.min] Minimum backoff duration in ms
 * @param {number} [opts.max] Maximum backoff duration in ms
 */
class Backoff {
  min: number
  max: number
  attempts: number

  constructor({ min = 100, max = 10000 } = {}) {
    this.min = min
    this.max = max
    this.attempts = 0
  }

  /**
   * Get backoff duration
   *
   * @returns {number} Backoff duration in ms
   */

  duration() {
    const ms = this.min * 2 ** this.attempts
    this.attempts += 1
    return Math.min(ms, this.max)
  }
}

/**
 * Retry promise
 *
 * @param {function} fn Function returning promise that should be retried
 * @param {number} attempts Maximum number of attempts
 * @param {Backoff} backoff Backoff instance
 * @returns {Promise}
 */
async function retryPromise(
  fn: (arg0: () => unknown) => unknown,
  attempts: number,
  backoff: Backoff
): Promise<unknown> {
  let aborted = false

  try {
    const data = await fn(() => {
      aborted = true
    })
    return data
  } catch (e) {
    if (aborted || backoff.attempts + 1 >= attempts) {
      throw e
    }

    const duration = backoff.duration()
    log.info(
      `Promise rejected attempt #${backoff.attempts}, retrying in ${duration}ms: ${e}`
    )

    await new Promise((resolve) => {
      setTimeout(resolve, duration, {})
    })
    return retryPromise(fn, attempts, backoff)
  }
}

/**
 * Retry promise
 *
 * @param {function} fn Function returning promise that should be retried
 * @param {object} [backoffOpts] Backoff options
 * @param {number} [backoffOpts.attempts] Maximum number of attempts, default: `5`
 * @param {number} [backoffOpts.min] Minimum attempt delay in milliseconds, default: `5000`
 * @param {number} [backoffOpts.max] Maximum attempt delay in milliseconds, default: `30000`
 * @returns {Promise}
 */
export function retry(
  fn: (arg0: () => unknown) => unknown,
  { attempts = 5, min = 5000, max = 30000 } = {}
): Promise<unknown> {
  const backoff = new Backoff({ min, max })
  return retryPromise(fn, attempts, backoff)
}

/**
 * Converts a PEM encoded private key to a CryptoKey object using the WebCrypto API.
 *
 * @param {string} pem - The PEM encoded private key.
 * @returns {Promise<CryptoKey>} A Promise that resolves with the CryptoKey object.
 * @throws {Error} If the key type is not supported or the format is invalid.
 */
export async function importPemPrivateKey(pem: string): Promise<CryptoKey> {
  // Decode PEM string to Uint8Array
  const pemData = pemToBuffer(pem, 'PRIVATE KEY')

  // Parse PEM data to ASN.1 structure using pkijs
  const asn1 = asn1js.fromBER(pemData.buffer)
  const privateKeyInfo = new pkijs.PrivateKeyInfo({ schema: asn1.result })

  // Use crypto.subtle.importKey to import private key as CryptoKey
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyInfo.toSchema().toBER(false),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign']
  )

  return privateKey
}

/**
 * Converts a PEM encoded string to a Buffer.
 * @param {string} pem Pem encoded input
 * @param {string} tag The tag name used to identify the PEM block.
 * @returns Buffer
 */
export function pemToBuffer(pem: string, tag: PemTag = 'PRIVATE KEY'): Buffer {
  return Buffer.from(
    pem.replace(
      new RegExp(`(-----BEGIN ${tag}-----|-----END ${tag}-----|\n)`, 'g'),
      ''
    ),
    'base64'
  )
}

export type CertificateInfo = {
  issuer: {
    [x: string]: string
  }[]
  domains: CertDomains
  notBefore: Date
  notAfter: Date
}
/**
 * Read information from a certificate
 * If multiple certificates are chained, the first will be read
 *
 * @param {buffer|string} certPem PEM encoded certificate or chain
 * @returns {CertificateInfo} Certificate info
 */
export async function readCertificateInfo(
  certPem: string
): Promise<CertificateInfo> {
  const certBuffer = pemToBuffer(certPem, 'CERTIFICATE')
  const cert = pkijs.Certificate.fromBER(certBuffer)

  const issuer = cert.issuer.typesAndValues.map((typeAndValue) => ({
    [typeAndValue.type]: typeAndValue.value.valueBlock.value,
  }))

  return {
    issuer,
    domains: readX509ServerNames(certPem),
    notBefore: cert.notBefore.value,
    notAfter: cert.notAfter.value,
  }
}

/**
 * Split chain of PEM encoded objects from string into array
 *
 * @param {buffer|string} chainPem PEM encoded object chain
 * @returns {array} Array of PEM objects including headers
 */
export function splitPemChain(chainPem: Buffer | string): (string | null)[] {
  if (Buffer.isBuffer(chainPem)) {
    chainPem = chainPem.toString()
  }
  return (
    chainPem
      /* Split chain into chunks, starting at every header */
      .split(/\s*(?=-----BEGIN [A-Z0-9- ]+-----\r?\n?)/g)
      /* Match header, PEM body and footer */
      .map((pem) =>
        pem.match(
          /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\S\s]+)\r?\n?-----END \1-----/
        )
      )
      /* Filter out non-matches or empty bodies */
      .filter((pem) => pem && pem[2] && pem[2].replace(/[\r\n]+/g, '').trim())
      .map((arr) => arr && arr[0])
  )
}

export type CertDomains = {
  commonName: string
  altNames: string[]
}
/**
 * Given a `domains` object, which follows the format returned by readX509ServerNames(),
 * returns
 * @param domains CertDomains
 */
export function uniqueDomains(domains: CertDomains): string[] {
  const uniqueDomains = [domains.commonName]
  for (const altName of domains.altNames) {
    if (uniqueDomains.indexOf(altName) === -1) {
      uniqueDomains.push(altName)
    }
  }
  return uniqueDomains
}

/**
 * Reads the common name and alternative names from a PEM-formatted cert or CSR
 * (Certificate Signing Request).
 * @param certPem The PEM-encoded cert or CSR string or a Buffer containing the same.
 * @returns An object with the commonName and altNames extracted from the cert/CSR.
 *          If the cert does not have alternative names, altNames will be empty.
 */
export function readX509ServerNames(certPem: string | Buffer): CertDomains {
  if (Buffer.isBuffer(certPem)) {
    certPem = certPem.toString()
  }
  const csr = x509.parse_pem_cert(certPem)

  // for some reason, get_oid_value for altNames returns a nested array, e.g.
  // [['host1','host2']], so make it a normal array if necessary
  let altNames: string[] = []
  const origAltNames = x509.get_oid_value(
    csr,
    '2.5.29.17'
  ) as unknown as string[][]
  if (origAltNames && origAltNames[0] && origAltNames[0][0]) {
    altNames = origAltNames[0]
  }

  return {
    commonName: x509.get_oid_value(csr, '2.5.4.3'),
    altNames,
  }
}

/**
 * Convenience method to return the value of a given environment variable or
 * nginx variable. Will return the environment variable if that is found first.
 * Requires that env vars be the uppercase version of nginx vars.
 * If no default is given and the variable is not found, throws an error.
 * @param r Nginx HTTP Request
 * @param varname Name of the variable
 * @returns value of the variable
 */
export function getVariable(
  r: NginxHTTPRequest | NginxPeriodicSession,
  varname:
    | 'njs_acme_account_email'
    | 'njs_acme_server_names'
    | 'njs_acme_dir'
    | 'njs_acme_challenge_dir'
    | 'njs_acme_account_private_jwk'
    | 'njs_acme_directory_uri'
    | 'njs_acme_verify_provider_https'
    | 'njs_acme_shared_dict_zone_name',
  defaultVal?: string
): string {
  const retval =
    process.env[varname.toUpperCase()] || r.variables[varname] || defaultVal
  if (retval === undefined) {
    const errMsg = `Variable ${varname} not found and no default value given.`
    log.error(errMsg)
    throw new Error(errMsg)
  }
  return retval
}

/**
 * Return the hostname to use as the common name for issued certs. This is the first hostname in the njs_acme_server_names variable.
 * @param r request
 * @returns {string} hostname
 */
export function acmeCommonName(
  r: NginxHTTPRequest | NginxPeriodicSession
): string {
  // The first name is the common name
  return acmeServerNames(r)[0]
}

/**
 * Return the hostname to use as the common name for issued certs. This is the first hostname in the njs_acme_server_names variable.
 * @param r request
 * @returns {string} hostname
 */
export function acmeAltNames(
  r: NginxHTTPRequest | NginxPeriodicSession
): string[] {
  const serverNames = acmeServerNames(r)
  if (serverNames.length <= 1) {
    // no alt names
    return []
  }
  // Return everything after the first name
  return serverNames.slice(1)
}

/**
 * Return an array of hostnames specified in the njs_acme_server_names variable
 * @param r request
 * @returns array of hostnames
 */
export function acmeServerNames(
  r: NginxHTTPRequest | NginxPeriodicSession
): string[] {
  const nameStr = getVariable(r, 'njs_acme_server_names') // no default == mandatory
  // split string value on comma and/or whitespace and lowercase each element
  const names = nameStr.split(/[,\s]+/)
  const invalidNames = names.filter((name) => !isValidHostname(name))

  if (invalidNames.length > 0) {
    const errMsg =
      'Invalid hostname(s) in `njs_acme_server_names` detected: ' +
      invalidNames.join(', ')
    log.error(errMsg)
    throw new Error(errMsg)
  }
  return names.map((n) => n.toLowerCase())
}

/**
 * Return the path where ACME magic happens
 * @param r request
 * @returns configured path or default
 */
export function acmeDir(r: NginxHTTPRequest | NginxPeriodicSession): string {
  return getVariable(r, 'njs_acme_dir', '/etc/nginx/njs-acme')
}

/**
 * Return the shared_dict zone name
 * @param r request
 * @returns configured shared_dict zone name or default
 */
export function acmeZoneName(
  r: NginxHTTPRequest | NginxPeriodicSession
): string {
  return getVariable(r, 'njs_acme_shared_dict_zone_name', 'acme')
}
/**
 * Return the path where ACME challenges are stored
 * @param r request
 * @returns configured path or default
 */
export function acmeChallengeDir(
  r: NginxHTTPRequest | NginxPeriodicSession
): string {
  return getVariable(
    r,
    'njs_acme_challenge_dir',
    joinPaths(acmeDir(r), 'challenge')
  )
}

/**
 * Returns the path for the account private JWK
 * @param r {NginxHTTPRequest | NginxPeriodicSession}
 */
export function acmeAccountPrivateJWKPath(
  r: NginxHTTPRequest | NginxPeriodicSession
): string {
  return getVariable(
    r,
    'njs_acme_account_private_jwk',
    joinPaths(acmeDir(r), 'account_private_key.json')
  )
}

/**
 * Returns the ACME directory URI
 * @param r {NginxHTTPRequest | NginxPeriodicSession}
 */
export function acmeDirectoryURI(
  r: NginxHTTPRequest | NginxPeriodicSession
): string {
  return getVariable(
    r,
    'njs_acme_directory_uri',
    'https://acme-staging-v02.api.letsencrypt.org/directory'
  )
}

/**
 * Returns whether to verify the ACME provider HTTPS certificate and chain
 * @param r {NginxHTTPRequest | NginxPeriodicSession}
 * @returns boolean
 */
export function acmeVerifyProviderHTTPS(
  r: NginxHTTPRequest | NginxPeriodicSession
): boolean {
  return (
    ['true', 'yes', '1'].indexOf(
      getVariable(r, 'njs_acme_verify_provider_https', 'true')
        .toLowerCase()
        .trim()
    ) > -1
  )
}

export function areEqualSets(arr1: string[], arr2: string[]): boolean {
  if (arr1.length !== arr2.length) {
    return false
  }
  for (const elem of arr1) {
    if (arr2.indexOf(elem) === -1) {
      return false
    }
  }
  return true
}

/**
 * Joins args with slashes and removes duplicate slashes
 * @param args path fragments to join
 * @returns joined path string
 */
export function joinPaths(...args: string[]): string {
  // join args with a slash remove duplicate slashes
  return args.join('/').replace(/\/+/g, '/')
}

export function isValidHostname(hostname: string): boolean {
  return (
    !!hostname &&
    hostname.length < 256 &&
    !!hostname.match(
      // hostnames are dot-separated groups of letters, numbers, hyphens (but
      // not beginning or ending with hyphens), and may end with a period
      /^[a-z\d]([-a-z\d]{0,61}[a-z\d])?(\.[a-z\d]([-a-z\d]{0,61}[a-z\d])?)*\.?$/i
    )
  )
}

/**
 * Return the certificate
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The contents of the cert or key
 */
export function readCert(r: NginxHTTPRequest): string {
  return readCertOrKey(r, CERTIFICATE_SUFFIX)
}

/**
 * Return the certificate
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The contents of the cert or key
 */
export function readKey(r: NginxHTTPRequest): string {
  return readCertOrKey(r, KEY_SUFFIX)
}

/**
 * Given a request and suffix that indicates whether the caller wants the cert
 * or key, return the requested object from cache if possible, falling back to
 * disk.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @param {string} suffix - The file suffix that indicates whether we want a cert or key
 * @returns {string} - The contents of the cert or key
 */
function readCertOrKey(
  r: NginxHTTPRequest,
  suffix: typeof CERTIFICATE_SUFFIX | typeof KEY_SUFFIX
): string {
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
