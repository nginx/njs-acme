import {
  formatResponseError,
  getPublicJwk,
  RsaPublicJwk,
  EcdsaPublicJwk,
} from './utils'
import { Logger, LogLevel } from './logger'
import { version } from '../package.json'
import {
  AccountCreateRequest,
  AccountUpdateRequest,
  ClientExternalAccountBindingOptions,
  OrderCreateRequest,
} from './client'
import OGCrypto from 'crypto'

export type AcmeMethod = 'GET' | 'HEAD' | 'POST' | 'POST-as-GET'
export type AcmeResource =
  | 'newNonce'
  | 'newAccount'
  | 'newAuthz'
  | 'newOrder'
  | 'revokeCert'
  | 'keyChange'
  | 'renewalInfo'
export type AcmeSignAlgo = 'RS256' | 'ES256' | 'ES512' | 'ES384'

export interface SignedPayload {
  payload: string
  protected: string
  signature?: string
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

type ApiPayload =
  | Record<string, unknown>
  | AccountCreateRequest
  | OrderCreateRequest
  | SignedPayload
  | RsaPublicJwk
  | EcdsaPublicJwk
  | null
  | undefined

export type UpdateAuthorizationData = {
  status: string
}

export interface DirectoryMetadata {
  /**
   * A URL identifying the current terms of service
   */
  termsOfService?: string

  /**
   * An HTTP or HTTPS URL locating a website providing more information
   * about the ACME server
   */
  website?: string

  /**
   * The hostnames that the ACME server recognizes as referring to itself
   * for the purposes of CAA record validation
   *
   * NOTE:
   * Each string MUST represent the same sequence of ASCII code points
   * that the server will expect to see as the "Issuer Domain Name"
   * in a CAA issue or issue wild property tag. This allows clients
   * to determine the correct issuer domain name to use
   * when configuring CAA records
   */
  caaIdentities?: string[]

  /**
   * If this field is present and set to "true", then the CA requires
   * that all newAccount requests include an "externalAccountBinding"
   * field associating the new account with an external account
   */
  externalAccountRequired?: boolean

  /**
   *
   */
  endpoints?: string[]
}

export interface AcmeDirectory {
  /**
   * New nonce.
   */
  newNonce: string

  /**
   * New account.
   */
  newAccount: string

  /**
   * New authorization
   */
  newAuthz?: string

  /**
   * New order.
   */
  newOrder: string

  /**
   * Revoke certificate
   */
  revokeCert: string

  /**
   * Key change
   */
  keyChange: string

  /**
   * Metadata object
   */
  meta?: DirectoryMetadata

  /**
   * draft-ietf-acme-ari-00
   */
  renewalInfo?: string
}

/**
 * Directory URLs for various ACME providers
 */
export const directories = {
  buypass: {
    staging: 'https://api.test4.buypass.no/acme/directory',
    production: 'https://api.buypass.com/acme/directory',
  },
  letsencrypt: {
    staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    production: 'https://acme-v02.api.letsencrypt.org/directory',
  },
  zerossl: {
    production: 'https://acme.zerossl.com/v2/DV90',
  },
  pebble: {
    // Let's encrypt for testing https://github.com/letsencrypt/pebble
    staging: 'https://localhost:14000/dir',
  },
}

/**
 * ACME HTTP client
 *
 * @class HttpClient
 * @param directoryUrl {string} URL to the ACME directory.
 * @param accountKey {CryptoKey} Private key to use for signing requests.
 * @param accountUrl [string] (optional) URL of the account, if it has already been registered.
 * @param externalAccountBinding [ClientExternalAccountBindingOptions] (optional) External account binding options
 * @param verify {boolean} (optional) Enables or disables verification of the HTTPS server certificate while making requests. Defaults to `true`.
 * @param debug {boolean} (optional) Enables debug mode. Defaults to `false`.
 * @param maxBadNonceRetries {number} (optional) Maximum number of retries when encountering a bad nonce error. Defaults to 5.
 */
export class HttpClient {
  /**
   * The URL for the ACME directory.
   * @type {string}
   */
  directoryUrl: string

  /**
   * The cryptographic key pair used for signing requests.
   * @type {CryptoKey}
   */
  accountKey: CryptoKey

  /**
   * An object that contains external account binding information.
   * @type {ClientExternalAccountBindingOptions}
   */
  externalAccountBinding: ClientExternalAccountBindingOptions

  /**
   * The ACME directory.
   * @type {?AcmeDirectory}
   */
  directory: AcmeDirectory | null

  /**
   * The public key in JWK format.
   * @type {?RsaPublicJwk | ?EcdsaPublicJwk}
   */
  jwk: RsaPublicJwk | EcdsaPublicJwk | null | undefined

  /**
   * The URL for the ACME account.
   * @type {?string}
   */
  accountUrl: string | null | undefined

  /**
   * Determines whether to verify the HTTPS server certificate while making requests.
   * @type {boolean}
   */
  verify: boolean

  /**
   * The maximum number of retries allowed when encountering a bad nonce.
   * @type {number}
   */
  maxBadNonceRetries: number

  private readonly log: Logger

  /**
   * Creates an instance of the ACME HTTP client.
   * @constructor
   * @param {string} directoryUrl - The URL of the ACME directory.
   * @param {CryptoKey} accountKey - The private key to use for ACME account operations.
   * @param {string} [accountUrl=""] - The URL of the ACME account. If not provided, a new account will be created.
   * @param {ClientExternalAccountBindingOptions} [externalAccountBinding={ kid: "", hmacKey: "" }] - The external account binding options for the client.
   * @returns {HttpClient} The newly created instance of the ACME HTTP client.
   */
  constructor(
    directoryUrl: string,
    accountKey: CryptoKey,
    accountUrl = '',
    externalAccountBinding: ClientExternalAccountBindingOptions = {
      kid: '',
      hmacKey: '',
    }
  ) {
    this.directoryUrl = directoryUrl
    this.accountKey = accountKey
    this.externalAccountBinding = externalAccountBinding

    this.directory = null
    this.jwk = null
    this.accountUrl = accountUrl
    this.verify = true
    this.maxBadNonceRetries = 5
    this.log = new Logger('http', LogLevel.Info)
  }

  /**
   * HTTP request
   *
   * @param {string} url HTTP URL
   * @param {string} method HTTP method
   * @param {string} [body] Request options
   * @returns {Promise<Response>} HTTP response
   */
  async request(url: string, method: AcmeMethod, body = ''): Promise<Response> {
    const options: NgxFetchOptions = {
      headers: {
        'user-agent': `njs-acme-v${version}`,
        'Content-Type': 'application/jose+json',
      },
      method: method,
      body: body,
      verify: this.verify || false,
    }

    /* Request */
    this.log.debug('Sending a new request:', method, url, options)
    const resp = await ngx.fetch(url, options)
    this.log.debug('Got a response:', resp.status, method, url, resp.headers)
    return resp
  }

  /**
   * Sends a signed request to the specified URL with the provided payload.
   * https://tools.ietf.org/html/rfc8555#section-6.2
   *
   * @async
   * @param {string} url - The URL to send the request to.
   * @param {object} payload - The request payload to send.
   * @param {object} options - An object containing optional parameters.
   * @param {string} [options.kid=null] - The kid parameter for the request.
   * @param {string} [options.nonce=null] - The nonce parameter for the request.
   * @param {boolean} [options.includeExternalAccountBinding=false] - Whether to include the externalAccountBinding parameter in the request.
   * @param {number} [attempts=0] - The number of times the request has been attempted.
   * @returns {Promise<Response>} A Promise that resolves with the Response object for the request.
   */
  async signedRequest(
    url: string,
    payload: ApiPayload,
    {
      kid = null as string | null,
      nonce = null as string | null,
      includeExternalAccountBinding = false,
    } = {},
    attempts = 0
  ): Promise<Response> {
    if (!nonce) {
      nonce = await this.getNonce()
    }
    if (!this.jwk) {
      await this.getJwk()
    }

    this.log.debug('Signing request with:', { kid, nonce, jwt: this.jwk })

    /* External account binding

            https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4

            */
    if (includeExternalAccountBinding && this.externalAccountBinding) {
      if (
        this.externalAccountBinding.kid &&
        this.externalAccountBinding.hmacKey
      ) {
        const jwk = this.jwk
        const eabKid = this.externalAccountBinding.kid
        const eabHmacKey = this.externalAccountBinding.hmacKey

        // FIXME
        if (payload) {
          payload.externalAccountBinding = this.createSignedHmacBody(
            eabHmacKey,
            url,
            jwk,
            { kid: eabKid }
          )
        }
      }
    }

    /* Sign body and send request */
    const data = await this.createSignedBody(url, payload, { nonce, kid })
    this.log.debug('Signed request body:', data)
    const resp = await this.request(url, 'POST', JSON.stringify(data))

    if (resp.status === 400) {
      // Retry on bad nonce - https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.4
      // or bad response code.
      if (attempts < this.maxBadNonceRetries) {
        nonce = resp.headers.get('replay-nonce') || null
        attempts += 1

        this.log.warn(
          `Error response from server, retrying (${attempts}/${this.maxBadNonceRetries}) signed request to: ${url}`
        )
        return this.signedRequest(
          url,
          payload,
          { kid, nonce, includeExternalAccountBinding },
          attempts
        )
      }
    }
    /* Return response */
    return resp
  }

  /**
   * Sends a signed ACME API request with optional JWS authentication, nonce handling, and external account binding
   * request to the specified URL with the provided payload, and verifies the response status code.
   *
   * @param {string} url - The URL to make the API request to.
   * @param {any} [payload=null] - The payload to include in the API request.
   * @param {number[]} [validStatusCodes=[]] - An array of valid HTTP status codes.
   * @param {Object} [options={}] - An object of options for the API request.
   * @param {boolean} [options.includeJwsKid=true] - Whether to include the JWS kid header in the API request.
   * @param {boolean} [options.includeExternalAccountBinding=false] - Whether to include the external account binding in the API request.
   * @returns {Promise<Response>} - A promise that resolves with the API response.
   * @throws {Error} When an unexpected status code is returned in the HTTP response, with the corresponding error message returned in the response body.
   */
  async apiRequest(
    url: string,
    payload: ApiPayload = null,
    validStatusCodes: number[] = [],
    { includeJwsKid = true, includeExternalAccountBinding = false } = {}
  ): Promise<Response> {
    const kid = includeJwsKid ? this.getAccountUrl() : null
    this.log.debug('Preparing a new api request:', { kid, payload })
    const resp = await this.signedRequest(url, payload, {
      kid,
      includeExternalAccountBinding,
    })

    if (
      validStatusCodes.length &&
      validStatusCodes.indexOf(resp.status) === -1
    ) {
      const b = await resp.json()
      this.log.warn(
        `Received unexpected status code ${resp.status} for API request ${url}.`,
        'Expected status codes:',
        validStatusCodes,
        'Body response:',
        b
      )

      const e = formatResponseError(b)
      throw new Error(e)
    }
    return resp
  }

  /**
   * ACME API request by resource name helper
   *
   * @private
   * @param {string} resource Request resource name
   * @param {object} [payload] Request payload, default: `null`
   * @param {array} [validStatusCodes] Array of valid HTTP response status codes, default: `[]`
   * @param {object} [opts]
   * @param {boolean} [opts.includeJwsKid] Include KID instead of JWK in JWS header, default: `true`
   * @param {boolean} [opts.includeExternalAccountBinding] Include EAB in request, default: `false`
   * @returns {Promise<object>} HTTP response
   */
  async apiResourceRequest(
    resource: AcmeResource,
    payload: ApiPayload,
    validStatusCodes: number[] = [],
    { includeJwsKid = true, includeExternalAccountBinding = false } = {}
  ): Promise<Response> {
    const resourceUrl = await this.getResourceUrl(resource)
    return this.apiRequest(resourceUrl, payload, validStatusCodes, {
      includeJwsKid,
      includeExternalAccountBinding,
    })
  }

  /**
   * Retrieves the ACME directory from the directory URL specified in the constructor.
   *
   * @throws {Error} Throws an error if the response status code is not 200 OK or the response body is invalid.
   * @returns {Promise<void>} Updates internal `this.directory` and returns a promise
   */
  async getDirectory(): Promise<void> {
    if (!this.directory) {
      const resp = await this.request(this.directoryUrl, 'GET')

      if (resp.status >= 400) {
        throw new Error(
          `Attempting to read ACME directory returned error ${resp.status}: ${this.directoryUrl}`
        )
      }
      const data = (await resp.json()) as AcmeDirectory
      if (!data) {
        throw new Error('Attempting to read ACME directory returned no data')
      }
      this.directory = data
      this.log.debug('Fetched directory:', this.directory)
    }
  }

  /**
   * Retrieves the public key associated with the account key
   *
   * @async
   * @function getJwk
   * @returns {Promise<RsaPublicJwk|EcdsaPublicJwk|null>} The public key associated with the account key, or null if not found
   * @throws {Error} If the account key is not set or is not valid
   */
  async getJwk(): Promise<RsaPublicJwk | EcdsaPublicJwk> {
    // singleton
    if (!this.jwk) {
      this.log.debug(
        'Public JWK not set. Obtaining it from Account Private Key...'
      )
      this.jwk = await getPublicJwk(this.accountKey)
      this.log.debug('Obtained Account Public JWK:', this.jwk)
    }
    return this.jwk
  }

  /**
   * Get nonce from directory API endpoint
   *
   * https://tools.ietf.org/html/rfc8555#section-7.2
   *
   * @returns {Promise<string>} nonce
   */
  async getNonce(): Promise<string> {
    const url = await this.getResourceUrl('newNonce')
    const resp = await this.request(url, 'HEAD')
    if (!resp.headers.get('replay-nonce')) {
      this.log.error('No nonce from ACME provider. "replay-nonce" header found')
      throw new Error('Failed to get nonce from ACME provider')
    }
    return resp.headers.get('replay-nonce')
  }

  /**
   * Get URL for a directory resource
   *
   * @param {string} resource API resource name
   * @returns {Promise<string>} URL
   */
  async getResourceUrl(resource: AcmeResource): Promise<string> {
    await this.getDirectory()

    if (this.directory != null && !this.directory[resource]) {
      this.log.error(
        `Unable to locate API resource URL in ACME directory: "${resource}"`
      )
      throw new Error(
        `Unable to locate API resource URL in ACME directory: "${resource}"`
      )
    }
    if (!this.directory) {
      throw new Error('this.directory is null')
    }
    return this.directory[resource] as string
  }

  /**
   * Get directory meta field
   *
   * @param {string} field Meta field name
   * @returns {Promise<string | boolean | string[] | undefined>} Meta field value
   */
  async getMetaField(
    field:
      | 'termsOfService'
      | 'website'
      | 'caaIdentities'
      | 'externalAccountRequired'
      | 'endpoints'
  ): Promise<string | boolean | string[] | undefined> {
    await this.getDirectory()
    if (!this.directory) {
      throw new Error('this.directory is null')
    }
    return this.directory?.meta?.[field]
  }

  /**
   * Prepares a signed request body to be sent to an ACME server.
   * @param {AcmeSignAlgo|string} alg - The signing algorithm to use.
   * @param {NjsStringLike} url - The URL to include in the signed payload.
   * @param {Object|null} [payload=null] - The payload to include in the signed payload.
   * @param {RsaPublicJwk|EcdsaPublicJwk|null|undefined} [jwk=null] - The JWK to use for signing the payload.
   * @param {Object} [options={nonce: null, kid: null}] - Additional options for the signed payload.
   * @param {string|null} [options.nonce=null] - The nonce to include in the signed payload.
   * @param {string|null} [options.kid=null] - The KID to include in the signed payload.
   * @returns {SignedPayload} The signed payload.
   */
  prepareSignedBody(
    alg: AcmeSignAlgo | string,
    url: string,
    payload: ApiPayload = null,
    jwk: RsaPublicJwk | EcdsaPublicJwk | null | undefined,
    { nonce = null as string | null, kid = null as string | null } = {}
  ): SignedPayload {
    const header: Record<string, unknown> = { alg, url }

    /* Nonce */
    if (nonce) {
      header.nonce = nonce
    }

    /* KID or JWK */
    if (kid) {
      header.kid = kid
    } else {
      header.jwk = jwk
    }

    /* Body */
    const body: SignedPayload = {
      payload: payload
        ? Buffer.from(JSON.stringify(payload)).toString('base64url')
        : '',
      protected: Buffer.from(JSON.stringify(header)).toString('base64url'),
    }
    return body
  }

  /**
   * Creates a signed HMAC body for the given URL and payload, with optional nonce and kid parameters
   *
   * @param {string} hmacKey The key to use for the HMAC signature.
   * @param {string} url The URL to sign.
   * @param {object} [payload] The payload to sign. Defaults to null.
   * @param {object} [opts] Optional parameters for the signature (nonce and kid).
   * @param {string} [opts.nonce] The anti-replay nonce to include in the signature. Defaults to null.
   * @param {string} [opts.kid] The kid to include in the signature. Defaults to null.
   * @returns {object} Signed HMAC request body
   * @throws An error if the HMAC key is not provided.
   */
  async createSignedHmacBody(
    hmacKey: string,
    url: string,
    payload: ApiPayload = null,
    { nonce = null as string | null, kid = null as string | null } = {}
  ): Promise<SignedPayload> {
    if (!hmacKey) {
      throw new Error('HMAC key is required.')
    }
    const result = this.prepareSignedBody('HS256', url, payload, null, {
      nonce,
      kid,
    })
    const h = OGCrypto.createHmac('sha256', Buffer.from(hmacKey, 'base64'))
    h.update(`${result.protected}.${result.payload}`)
    result.signature = h.digest('base64url')
    return result
  }

  /**
   * Create JWS HTTP request body using RSA or ECC
   *
   * https://datatracker.ietf.org/doc/html/rfc7515
   *
   * @param {string} url Request URL
   * @param {object} [payload] Request payload
   * @param {object} [opts]
   * @param {string} [opts.nonce] JWS nonce
   * @param {string} [opts.kid] JWS KID
   * @returns {Promise<SignedPayload>} JWS request body
   */
  async createSignedBody(
    url: string,
    payload: ApiPayload = null,
    { nonce = null as string | null, kid = null as string | null } = {}
  ): Promise<SignedPayload> {
    const jwk = this.jwk
    let headerAlg: AcmeSignAlgo = 'RS256'
    let signerAlg = 'SHA-256'

    if (!jwk) {
      throw new Error('jwk is undefined')
    }
    /* https://datatracker.ietf.org/doc/html/rfc7518#section-3.1 */
    if ('crv' in jwk && jwk.crv && jwk.kty === 'EC') {
      headerAlg = 'ES256'
      if (jwk.crv === 'P-384') {
        headerAlg = 'ES384'
        signerAlg = 'SHA-384'
      } else if (jwk.crv === 'P-521') {
        headerAlg = 'ES512'
        signerAlg = 'SHA-512'
      }
    }

    /* Prepare body and sign it */
    const result = this.prepareSignedBody(headerAlg, url, payload, jwk, {
      nonce,
      kid,
    })

    this.log.debug('Prepared signed payload', result)

    let sign
    if (jwk.kty === 'EC') {
      const hash = await crypto.subtle.digest(
        signerAlg as HashVariants,
        `${result.protected}.${result.payload}`
      )
      sign = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: hash.toString() as HashVariants,
        },
        this.accountKey,
        hash
      )
    } else {
      sign = await crypto.subtle.sign(
        { name: 'RSASSA-PKCS1-v1_5' },
        this.accountKey,
        `${result.protected}.${result.payload}`
      )
    }

    result.signature = Buffer.from(sign).toString('base64url')
    return result
  }

  /**
   * Returns the account URL associated with the current client instance.
   *
   * @private
   * @returns {string} the account URL
   * @throws {Error} If no account URL has been set yet
   */
  getAccountUrl(): string {
    if (!this.accountUrl) {
      throw new Error('No account URL found, register account first')
    }
    return this.accountUrl
  }

  /**
   * Get Terms of Service URL if available
   *
   * https://tools.ietf.org/html/rfc8555#section-7.1.1
   *
   * @returns {Promise<string|null>} ToS URL
   */
  async getTermsOfServiceUrl(): Promise<string | undefined> {
    return this.getMetaField('termsOfService') as Promise<string>
  }

  /**
   * Create new account
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3
   *
   * @param {object} data Request payload.
   * @param {boolean} data.termsOfServiceAgreed Whether the client agrees to the terms of service.
   * @param {[]string} data.contact An array of contact info, e.g. ['mailto:admin@example.com'].
   * @param {boolean} data.onlyReturnExisting Whether the server should only return an existing account, or create a new one if it does not exist.
   * @returns {Promise<object>} HTTP response.
   */
  async createAccount(data: AccountCreateRequest): Promise<Response> {
    const resp = await this.apiResourceRequest('newAccount', data, [200, 201], {
      includeJwsKid: false,
      includeExternalAccountBinding: data.onlyReturnExisting !== true,
    })

    /* Set account URL */
    if (resp.headers.get('location')) {
      this.accountUrl = resp.headers.get('location')
    }

    return resp
  }

  /**
   * Update account
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3.2
   *
   * @param {object} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  updateAccount(data: AccountUpdateRequest): Promise<Response> {
    return this.apiRequest(this.getAccountUrl(), data, [200, 202])
  }

  /**
   * Update account key
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3.5
   *
   * @param {ApiPayload} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  updateAccountKey(data: ApiPayload): Promise<Response> {
    return this.apiResourceRequest('keyChange', data, [200])
  }

  /**
   * Create new order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {ApiPayload} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  createOrder(data: ApiPayload): Promise<Response> {
    return this.apiResourceRequest('newOrder', data, [201])
  }

  /**
   * Get order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {string} url Order URL
   * @returns {Promise<object>} HTTP response
   */
  getOrder(url: string): Promise<Response> {
    return this.apiRequest(url, null, [200])
  }

  /**
   * Finalize order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {string} url Finalization URL
   * @param {ApiPayload} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  finalizeOrder(url: string, data: ApiPayload): Promise<Response> {
    return this.apiRequest(url, data, [200])
  }

  /**
   * Get identifier authorization
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5
   *
   * @param {string} url Authorization URL
   * @returns {Promise<object>} HTTP response
   */
  getAuthorization(url: string): Promise<Response> {
    return this.apiRequest(url, null, [200])
  }

  /**
   * Update identifier authorization
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5.2
   *
   * @param {string} url Authorization URL
   * @param {object} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  updateAuthorization(
    url: string,
    data: UpdateAuthorizationData
  ): Promise<Response> {
    return this.apiRequest(url, data, [200])
  }

  /**
   * Completes a pending challenge with the ACME server by sending a response payload to the challenge URL.
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5.1
   *
   * @param {string} url Challenge URL
   * @param {ApiPayload} data Request payload
   * @returns {Promise<object>} HTTP response
   */
  completeChallenge(url: string, data: ApiPayload): Promise<Response> {
    return this.apiRequest(url, data, [200])
  }

  /**
   * Revoke certificate
   *
   * https://tools.ietf.org/html/rfc8555#section-7.6
   *
   *
   * @param {ApiPayload} data - An object containing the data needed for revocation:
   * @param {string} data.certificate - The certificate to be revoked.
   * @param {number} data.reason - An optional reason for revocation (default: 1).
   *                               See this https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
   * @returns {Promise<object>} HTTP response
   */
  revokeCert(data: ApiPayload): Promise<Response> {
    return this.apiResourceRequest('revokeCert', data, [200])
  }

  /**
   * Set the `verify` property to enable or disable verification of the HTTPS server certificate.
   *
   * @param {boolean} v - The value to set `verify` to.
   */
  setVerify(v: boolean): void {
    this.verify = v
  }

  /** how verbose these logs will be */
  get minLevel(): LogLevel {
    return this.log.minLevel
  }
  /** controls how verbose these logs will be */
  set minLevel(v: LogLevel) {
    this.log.minLevel = v
  }
}
