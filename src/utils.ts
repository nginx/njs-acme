import x509 from './x509.js'
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import fs from 'fs';
import querystring from 'querystring';

// workaround for PKI.JS to work
globalThis.unescape = querystring.unescape;

// make PKI.JS to work with webcrypto
pkijs.setEngine("webcrypto", new pkijs.CryptoEngine({ name: "webcrypto", crypto: crypto }));

// workaround for PKI.js toJSON/fromJson
// from https://stackoverflow.com/questions/36810940/alternative-or-polyfill-for-array-from-on-the-internet-explorer
if (!Array.from) {
  Array.from = (function () {
    var toStr = Object.prototype.toString;
    var isCallable = function (fn) {
      return typeof fn === 'function' || toStr.call(fn) === '[object Function]';
    };
    var toInteger = function (value) {
      var number = Number(value);
      if (isNaN(number)) { return 0; }
      if (number === 0 || !isFinite(number)) { return number; }
      return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
    };
    var maxSafeInteger = Math.pow(2, 53) - 1;
    var toLength = function (value) {
      var len = toInteger(value);
      return Math.min(Math.max(len, 0), maxSafeInteger);
    };

    // The length property of the from method is 1.
    return function from(arrayLike/*, mapFn, thisArg */) {
      // 1. Let C be the this value.
      var C = this;

      // 2. Let items be ToObject(arrayLike).
      var items = Object(arrayLike);

      // 3. ReturnIfAbrupt(items).
      if (arrayLike == null) {
        throw new TypeError("Array.from requires an array-like object - not null or undefined");
      }

      // 4. If mapfn is undefined, then let mapping be false.
      var mapFn = arguments.length > 1 ? arguments[1] : void undefined;
      var T;
      if (typeof mapFn !== 'undefined') {
        // 5. else
        // 5. a If IsCallable(mapfn) is false, throw a TypeError exception.
        if (!isCallable(mapFn)) {
          throw new TypeError('Array.from: when provided, the second argument must be a function');
        }

        // 5. b. If thisArg was supplied, let T be thisArg; else let T be undefined.
        if (arguments.length > 2) {
          T = arguments[2];
        }
      }

      // 10. Let lenValue be Get(items, "length").
      // 11. Let len be ToLength(lenValue).
      var len = toLength(items.length);

      // 13. If IsConstructor(C) is true, then
      // 13. a. Let A be the result of calling the [[Construct]] internal method of C with an argument list containing the single item len.
      // 14. a. Else, Let A be ArrayCreate(len).
      var A = isCallable(C) ? Object(new C(len)) : new Array(len);

      // 16. Let k be 0.
      var k = 0;
      // 17. Repeat, while k < len… (also steps a - h)
      var kValue;
      while (k < len) {
        kValue = items[k];
        if (mapFn) {
          A[k] = typeof T === 'undefined' ? mapFn(kValue, k) : mapFn.call(T, kValue, k);
        } else {
          A[k] = kValue;
        }
        k += 1;
      }
      // 18. Let putStatus be Put(A, "length", len, true).
      A.length = len;
      // 20. Return A.
      return A;
    };
  }());
}

export interface RsaPublicJwk {
  e: string;
  kty: string;
  n: string;
}

export interface EcdsaPublicJwk {
  crv: string;
  kty: string;
  x: string;
  y: string;
}

const ACCOUNT_KEY_ALG_GENERATE: RsaHashedKeyGenParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
}

const ACCOUNT_KEY_ALG_IMPORT: RsaHashedImportParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256"
}

/**
 * Generates RSA private and public key pair
 * @returns {CryptoKeyPair} a private and public key pair
 */
export async function generateKey() {
  const keys = (await crypto.subtle.generateKey(ACCOUNT_KEY_ALG_GENERATE, true, ["sign", "verify"]));
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
    const accountKeyJWK = fs.readFileSync(path, 'utf8');
    ngx.log(ngx.INFO, `acme-njs: [utils] Using account key from ${path}`);
    return await crypto.subtle.importKey('jwk', JSON.parse(accountKeyJWK), ACCOUNT_KEY_ALG_IMPORT, true, ["sign"]);
  } catch (e) {
    // TODO: separate file not found, issues with importKey
    ngx.log(ngx.WARN, `acme-njs: [utils] error ${e} while reading a private key from ${path}`);
    /* Generate a new RSA key pair for ACME account */
    const keys = (await generateKey()) as Required<CryptoKeyPair>;
    const jwkFormated = await crypto.subtle.exportKey("jwk", keys.privateKey)
    fs.writeFileSync(path, JSON.stringify(jwkFormated));
    ngx.log(ngx.INFO, `acme-njs: [utils] Generated a new account key and saved it to ${path}`);
    return keys.privateKey;
  }
}


/**
 * Gets the public JWK from a given private key.
 * @param {CryptoKey} privateKey - The private key to extract the public JWK from.
 * @returns {Promise<RsaPublicJwk | EcdsaPublicJwk>} The public JWK.
 * @throws {Error} Throws an error if the privateKey parameter is not provided or invalid.
 */
export async function getPublicJwk(privateKey: CryptoKey): Promise<RsaPublicJwk | EcdsaPublicJwk> {
  if (!privateKey) {
    const errMsg = 'Invalid or missing private key';
    ngx.log(ngx.ERR, errMsg);
    throw new Error(errMsg);
  }

  const jwk: any = await crypto.subtle.exportKey("jwk", privateKey);

  if (jwk.crv && (jwk.kty === 'EC')) {
    const { crv, x, y } = jwk;
    return {
      crv,
      kty: jwk.kty,
      x,
      y
    } as EcdsaPublicJwk;
  } else {
    return {
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    } as RsaPublicJwk;
  }
}

/**
 * Add line break every 64th character
 * @param pemString {string}
 * @returns  {string}
 */
export function formatPEM(pemString: string) {
  return pemString.replace(/(.{64})/g, '$1\n')
}

export type PemTag = "PRIVATE KEY" | "PUBLIC KEY" | "CERTIFICATE" | "CERTIFICATE REQUEST"

/**
 * Convert ArrayBufferView | ArrayBuffer to PEM string
 * @param buffer The ArrayBufferView | ArrayBuffer to convert to PEM
 * @param tag The tag to use for the PEM header and footer
 * @returns The converted PEM string
 */
export function toPEM(buffer: ArrayBufferView | ArrayBuffer, tag: PemTag): string {
  /**
   * Convert the ArrayBufferView or ArrayBuffer to base64 and format it
   * as a PEM string
   */
  const pemBody = formatPEM(Buffer.from(buffer).toString('base64'));

  // Construct and return the final PEM string
  return [
    `-----BEGIN ${tag}-----`,
    pemBody,
    `-----END ${tag}-----`,
    "",
  ].join("\n");
}


/**
 * Encodes a PKCS#10 certification request into an ASN.1 TBS (To-Be-Signed) sequence.
 *
 * @param pkcs10 The PKCS#10 certification request object to encode.
 * @returns An ASN.1 sequence object representing the TBS.
 */
export function encodeTBS(pkcs10: pkijs.CertificationRequest): asn1js.Sequence {
  const outputArray: any[] = [
    new asn1js.Integer({ value: pkcs10.version }),
    pkcs10.subject.toSchema(),
    pkcs10.subjectPublicKeyInfo.toSchema()
  ];

  if (pkcs10.attributes !== undefined) {
    outputArray.push(new asn1js.Constructed({
      idBlock: {
        tagClass: 3, // CONTEXT-SPECIFIC
        tagNumber: 0 // [0]
      },
      value: Array.from(pkcs10.attributes, o => o.toSchema())
    }));
  }

  return new asn1js.Sequence({
    value: outputArray
  });
}

interface AlgoCryptoKey extends CryptoKey {
  algorithm?: pkijs.CryptoEngineAlgorithmParams | { name: string }
}

/**
 * Returns signature parameters based on the private key and hash algorithm
 *
 * @param privateKey {CryptoKey} The private key used for the signature
 * @param hashAlgorithm {string} The hash algorithm used for the signature. Default is "SHA-1".
 * @returns {{signatureAlgorithm: pkijs.AlgorithmIdentifier; parameters: pkijs.CryptoEngineAlgorithmParams;}} An object containing signature algorithm and parameters
 */
function getSignatureParameters(privateKey: AlgoCryptoKey, hashAlgorithm = "SHA-1"): {
  signatureAlgorithm: pkijs.AlgorithmIdentifier; parameters: pkijs.CryptoEngineAlgorithmParams;
} {
  // Check hashing algorithm
  pkijs.getOIDByAlgorithm({ name: hashAlgorithm }, true, "hashAlgorithm");
  // Initial variables
  const signatureAlgorithm = new pkijs.AlgorithmIdentifier();


  privateKey.algorithm = {
    name: "RSASSA-PKCS1-V1_5"
  }

  //#region Get a "default parameters" for current algorithm
  const parameters = pkijs.getAlgorithmParameters(privateKey.algorithm.name, "sign");
  if (!Object.keys(parameters.algorithm).length) {
    const errMsg = 'Parameter `algorithm` is empty';
    ngx.log(ngx.ERR, errMsg);
    throw new Error(errMsg);
  }
  const algorithm = parameters.algorithm as any; // TODO remove `as any`
  algorithm.hash.name = hashAlgorithm;
  //#endregion

  //#region Fill internal structures base on "privateKey" and "hashAlgorithm"
  switch (privateKey.algorithm.name.toUpperCase()) {
    case "RSASSA-PKCS1-V1_5":
    case "ECDSA":
      signatureAlgorithm.algorithmId = pkijs.getOIDByAlgorithm(algorithm, true);
      break;
    case "RSA-PSS":
      {
        //#region Set "saltLength" as a length (in octets) of hash function result
        switch (hashAlgorithm.toUpperCase()) {
          case "SHA-256":
            algorithm.saltLength = 32;
            break;
          case "SHA-384":
            algorithm.saltLength = 48;
            break;
          case "SHA-512":
            algorithm.saltLength = 64;
            break;
          default:
        }
        //#endregion

        //#region Fill "RSASSA_PSS_params" object
        const paramsObject: Partial<pkijs.IRSASSAPSSParams> = {};

        if (hashAlgorithm.toUpperCase() !== "SHA-1") {
          const hashAlgorithmOID = pkijs.getOIDByAlgorithm({ name: hashAlgorithm }, true, "hashAlgorithm");

          paramsObject.hashAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: hashAlgorithmOID,
            algorithmParams: new asn1js.Null()
          });

          paramsObject.maskGenAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: "1.2.840.113549.1.1.8", // MGF1
            algorithmParams: paramsObject.hashAlgorithm.toSchema()
          });
        }

        if (algorithm.saltLength !== 20)
          paramsObject.saltLength = algorithm.saltLength;

        const pssParameters = new pkijs.RSASSAPSSParams(paramsObject);
        //#endregion

        //#region Automatically set signature algorithm
        signatureAlgorithm.algorithmId = "1.2.840.113549.1.1.10";
        signatureAlgorithm.algorithmParams = pssParameters.toSchema();
        //#endregion
      }
      break;
    default:
      const errMsg = `Unsupported signature algorithm: ${privateKey.algorithm.name}`;
      ngx.log(ngx.ERR, errMsg)
      throw new Error(errMsg);
  }
  //#endregion

  return {
    signatureAlgorithm,
    parameters
  };
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
  keySize?: number;
  commonName?: string;
  altNames?: string[];
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationUnit?: string;
  emailAddress?: string;
}): Promise<{ pkcs10Ber: ArrayBuffer; keys: Required<CryptoKeyPair> }> {
  // TODO:  allow to provide keys in addition to always generating one
  const { privateKey, publicKey } = (await generateKey()) as Required<CryptoKeyPair>;
  const algoPrivateKey = privateKey as AlgoCryptoKey;

  const pkcs10 = new pkijs.CertificationRequest();
  pkcs10.version = 0;

  addSubjectAttributes(pkcs10.subject.typesAndValues, params);
  await addExtensions(pkcs10, params, publicKey);

  // FIXME: workaround for PKIS.js
  algoPrivateKey.algorithm = pkijs.getAlgorithmParameters("RSASSA-PKCS1-v1_5", "sign")
  await signCsr(pkcs10, privateKey);

  const pkcs10Ber = getPkcs10Ber(pkcs10);

  return {
    pkcs10Ber,
    keys: { privateKey, publicKey },
  };
}

function addSubjectAttributes(
  subjectTypesAndValues: pkijs.AttributeTypeAndValue[],
  params: {
    country?: string;
    state?: string;
    organization?: string;
    organizationUnit?: string;
    commonName?: string;
  }
): void {
  if (params.country) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue("2.5.4.6", params.country)
    );
  }
  if (params.state) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue("2.5.4.8", params.state)
    );
  }
  if (params.organization) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue("2.5.4.10", params.organization)
    );
  }
  if (params.organizationUnit) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue("2.5.4.11", params.organizationUnit)
    );
  }
  if (params.commonName) {
    subjectTypesAndValues.push(
      createAttributeTypeAndValue("2.5.4.3", params.commonName)
    );
  }
}

function createAttributeTypeAndValue(
  type: string,
  value: string
): pkijs.AttributeTypeAndValue {
  return new pkijs.AttributeTypeAndValue({
    type,
    value: new asn1js.Utf8String({ value }),
  });
}

function getAltNames(params: {
  commonName?: string;
  altNames?: string[];
}): pkijs.GeneralName[] {
  const altNames: pkijs.GeneralName[] = [];

  if (params.altNames) {
    altNames.push(
      ...params.altNames.map((altName) =>
        createGeneralName(2, altName)
      )
    );
  }

  if (params.commonName && !altNames.some((name) => name.toString() === params.commonName)
  ) {
    altNames.push(createGeneralName(2, params.commonName));
  }

  return altNames;
}

function createGeneralName(
  type: 0 | 2 | 1 | 6 | 3 | 4 | 7 | 8 | undefined,
  value: string
): pkijs.GeneralName {
  return new pkijs.GeneralName({ type, value });
}

async function addExtensions(
  pkcs10: pkijs.CertificationRequest,
  params: { commonName?: string; altNames?: string[]; },
  publicKey: CryptoKey
) {

  const altNames = getAltNames(params);

  await pkcs10.subjectPublicKeyInfo.importKey(publicKey, pkijs.getCrypto(true));
  const subjectKeyIdentifier = await getSubjectKeyIdentifier(pkcs10);
  const altNamesGNs = new pkijs.GeneralNames({ names: altNames });
  const extensions = new pkijs.Extensions({
    extensions: [
      createExtension("2.5.29.14", subjectKeyIdentifier), // SubjectKeyIdentifier
      createExtension("2.5.29.17", altNamesGNs.toSchema()), // SubjectAltName
    ],
  });
  pkcs10.attributes = [];
  pkcs10.attributes.push(new pkijs.Attribute({
    type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
    values: [extensions.toSchema()],
  })
  );
}

function createExtension(
  extnID: string,
  extnValue: asn1js.BaseBlock
): pkijs.Extension {
  return new pkijs.Extension({
    extnID,
    critical: false,
    extnValue: extnValue.toBER(false),
  });
}

async function getSubjectKeyIdentifier(pkcs10: pkijs.CertificationRequest): Promise<asn1js.OctetString> {
  const subjectPublicKeyValue = pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex
  const subjectKeyIdentifier = await crypto.subtle.digest("SHA-256", subjectPublicKeyValue);
  return new asn1js.OctetString({ valueHex: subjectKeyIdentifier });
}

async function signCsr(pkcs10: pkijs.CertificationRequest, privateKey: AlgoCryptoKey): Promise<void> {
  /* Set signatureValue  */
  pkcs10.tbsView = new Uint8Array(encodeTBS(pkcs10).toBER());
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, pkcs10.tbsView);
  pkcs10.signatureValue = new asn1js.BitString({ valueHex: signature });

  /* Set signatureAlgorithm */
  const signatureParams = getSignatureParameters(privateKey, "SHA-256");
  pkcs10.signatureAlgorithm = signatureParams.signatureAlgorithm;
}

function getPkcs10Ber(pkcs10: pkijs.CertificationRequest): ArrayBuffer {
  return pkcs10.toSchema(true).toBER(false);
}


/**
 * Returns the Base64url encoded representation of the input data.
 *
 * @param {string} data - The data to be encoded.
 * @returns {string} - The Base64url encoded representation of the input data.
 */
export function getPemBodyAsB64u(data: string) {
  return Buffer.from(data).toString('base64url')
}


/**
 * Find and format error in response object
 *
 * @param {object} resp HTTP response
 * @returns {string} Error message
 */
export function formatResponseError(data: any) {
  let result;
  // const data = await resp.json();
  if ('error' in data) {
    result = data.error.detail || data.error;
  }
  else {
    result = data.detail || JSON.stringify(data);
  }

  return result.replace(/\n/g, '');
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
    this.min = min;
    this.max = max;
    this.attempts = 0;
  }


  /**
   * Get backoff duration
   *
   * @returns {number} Backoff duration in ms
   */

  duration() {
    const ms = this.min * (2 ** this.attempts);
    this.attempts += 1;
    return Math.min(ms, this.max);
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
async function retryPromise(fn: Function, attempts: number, backoff: Backoff): Promise<any> {
  let aborted = false;

  try {
    const data = await fn(() => { aborted = true; });
    return data;
  }
  catch (e) {
    if (aborted || ((backoff.attempts + 1) >= attempts)) {
      throw e;
    }

    const duration = backoff.duration();
    ngx.log(ngx.INFO, `acme-js: [utils] Promise rejected attempt #${backoff.attempts}, retrying in ${duration}ms: ${e}`);

    await new Promise((resolve) => { setTimeout(resolve, duration, {}); });
    return retryPromise(fn, attempts, backoff);
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
export function retry(fn: Function, { attempts = 5, min = 5000, max = 30000 } = {}) {
  const backoff = new Backoff({ min, max });
  return retryPromise(fn, attempts, backoff);
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
  const pemData = pemToBuffer(pem, 'PRIVATE KEY');

  // Parse PEM data to ASN.1 structure using pkijs
  const asn1 = asn1js.fromBER(pemData.buffer);
  const privateKeyInfo = new pkijs.PrivateKeyInfo({ schema: asn1.result });

  // Use crypto.subtle.importKey to import private key as CryptoKey
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyInfo.toSchema().toBER(false),
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    true,
    ['sign'],
  );

  return privateKey;
}

/**
 * Converts a PEM encoded string to a Buffer.
 * @param {string} pem Pem encoded input
 * @param {string} tag The tag name used to identify the PEM block.
 * @returns Buffer
 */
export function pemToBuffer(pem: string, tag: PemTag = 'PRIVATE KEY') {
  return Buffer.from(pem.replace(new RegExp(`(-----BEGIN ${tag}-----|-----END ${tag}-----|\n)`, 'g'), ''), 'base64');
}

/**
 * Read information from a certificate
 * If multiple certificates are chained, the first will be read
 *
 * @param {buffer|string} certPem PEM encoded certificate or chain
 * @returns {object} Certificate info
 */
export async function readCertificateInfo(certPem: string) {
  const domains = readCsrDomainNames(certPem);
  const certBuffer = pemToBuffer(certPem, "CERTIFICATE");
  const cert = pkijs.Certificate.fromBER(certBuffer);

  const issuer = cert.issuer.typesAndValues.map((typeAndValue) => ({
    [typeAndValue.type]: typeAndValue.value.valueBlock.value,
  }));
  const notBefore = cert.notBefore.value;
  const notAfter = cert.notAfter.value;
  return {
    issuer: issuer,
    domains: domains,
    notBefore: notBefore,
    notAfter: notAfter
  };
};


/**
 * Split chain of PEM encoded objects from string into array
 *
 * @param {buffer|string} chainPem PEM encoded object chain
 * @returns {array} Array of PEM objects including headers
 */
export function splitPemChain(chainPem: Buffer | string) {
  if (Buffer.isBuffer(chainPem)) {
    chainPem = chainPem.toString();
  }
  return chainPem
    /* Split chain into chunks, starting at every header */
    .split(/\s*(?=-----BEGIN [A-Z0-9- ]+-----\r?\n?)/g)
    /* Match header, PEM body and footer */
    .map((pem) => pem.match(/\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\S\s]+)\r?\n?-----END \1-----/))
    /* Filter out non-matches or empty bodies */
    .filter((pem) => pem && pem[2] && pem[2].replace(/[\r\n]+/g, '').trim())
    .map((arr) => arr && arr[0]);
}


/**
 * Reads the common name and alternative names from a CSR (Certificate Signing Request).
 * @param csrPem The PEM-encoded CSR string or a Buffer containing the CSR.
 * @returns An object with the commonName and altNames extracted from the CSR.
 *          If the CSR does not have alternative names, altNames will be false.
 */
export function readCsrDomainNames(csrPem: string | Buffer): { commonName: string, altNames: string[] | false } {
  if (Buffer.isBuffer(csrPem)) {
    csrPem = csrPem.toString();
  }
  var csr = x509.parse_pem_cert(csrPem);
  return {
    commonName: x509.get_oid_value(csr, "2.5.4.3"),
    altNames: x509.get_oid_value(csr, "2.5.29.17")
  };
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
export function getVariable(r: NginxHTTPRequest, varname: string, defaultVal?: string) {
  const retval = process.env[varname.toUpperCase()] || r.variables[varname] || defaultVal
  if (retval === undefined) {
    const errMsg = `Variable ${varname} not found and no default value given.`;
    ngx.log(ngx.ERR, errMsg);
    throw new Error(errMsg);
  }
  return retval
}


/**
 * Return an array of hostnames specified in the njs_acme_server_names variable
 * @param r request
 * @returns array of hostnames
 */
export function acmeServerNames(r: NginxHTTPRequest) {
  const nameStr = getVariable(r, 'njs_acme_server_names') // no default == mandatory
  // split string value on comma and/or whitespace and lowercase each element
  return nameStr.split(/[,\s]+/).map((n) => n.toLocaleLowerCase())
}


/**
 * Return the path where ACME magic happens
 * @param r request
 * @returns configured path or default
 */
export function acmeDir(r: NginxHTTPRequest) {
  return getVariable(r, 'njs_acme_dir', '/etc/acme');
}


/**
 * Returns the path for the account private JWK
 * @param r {NginxHTTPRequest}
 */
export function acmeAccountPrivateJWKPath(r: NginxHTTPRequest) {
  return getVariable(r, 'njs_acme_account_private_jwk',
    joinPaths(acmeDir(r), 'account_private_key.json')
  );
}


/**
 * Returns the ACME directory URI
 * @param r {NginxHTTPRequest}
 */
export function acmeDirectoryURI(r: NginxHTTPRequest) {
  return getVariable(r, 'njs_acme_directory_uri', 'https://acme-staging-v02.api.letsencrypt.org/directory');
}


/**
 * Returns whether to verify the ACME provider HTTPS certificate and chain
 * @param r {NginxHTTPRequest}
 * @returns boolean
 */
export function acmeVerifyProviderHTTPS(r: NginxHTTPRequest) {
  return ['true', 'yes', '1'].indexOf(
    getVariable(r, 'njs_acme_verify_provider_https', 'true').toLowerCase().trim()
  ) > -1;
}


/**
 * Joins args with slashes and removes duplicate slashes
 * @param args path fragments to join
 * @returns joined path string
 */
export function joinPaths(...args: string[]) {
  // join args with a slash remove duplicate slashes
  return args.join('/').replace(/\/+/g, '/')
}
