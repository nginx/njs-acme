import { HttpClient } from './api'
import { formatResponseError, getPemBodyAsB64u, retry } from './utils'
import OGCrypto from 'crypto'

export interface ClientExternalAccountBindingOptions {
  kid: string
  hmacKey: string
}

/* rfc 8555 */
/**
 * Account
 *
 * https://tools.ietf.org/html/rfc8555#section-7.1.2
 * https://tools.ietf.org/html/rfc8555#section-7.3
 * https://tools.ietf.org/html/rfc8555#section-7.3.2
 */
export interface Account {
  status: 'valid' | 'deactivated' | 'revoked'
  orders: string
  contact?: string[]
  termsOfServiceAgreed?: boolean
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

export interface AccountCreateRequest {
  contact?: string[]
  termsOfServiceAgreed?: boolean
  onlyReturnExisting?: boolean
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

export type AccountUpdateRequest = {
  status?: string
  contact?: string[]
  termsOfServiceAgreed?: boolean
  externalAccountBinding?: ClientExternalAccountBindingOptions
} | null

/**
 * Order
 *
 * https://tools.ietf.org/html/rfc8555#section-7.1.3
 * https://tools.ietf.org/html/rfc8555#section-7.4
 */
export interface Order {
  status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid'
  identifiers: Identifier[]
  authorizations: string[]
  finalize: string
  expires?: string
  notBefore?: string
  notAfter?: string
  error?: Record<string, unknown>
  certificate?: string
  url?: string
}

export interface OrderCreateRequest {
  identifiers: Identifier[]
  notBefore?: string
  notAfter?: string
  externalAccountBinding?: ClientExternalAccountBindingOptions
}

/**
 * Authorization
 *
 * https://tools.ietf.org/html/rfc8555#section-7.1.4
 */
export interface Authorization {
  identifier: Identifier
  status:
    | 'pending'
    | 'valid'
    | 'invalid'
    | 'deactivated'
    | 'expired'
    | 'revoked'
  challenges: Challenge[]
  expires?: string
  wildcard?: boolean
  url?: string
}

export interface Identifier {
  type: string
  value: string
}

/**
 * Challenge
 *
 * https://tools.ietf.org/html/rfc8555#section-8
 * https://tools.ietf.org/html/rfc8555#section-8.3
 * https://tools.ietf.org/html/rfc8555#section-8.4
 */
export interface ChallengeAbstract {
  type: string
  url: string
  status: 'pending' | 'processing' | 'valid' | 'invalid'
  validated?: string
  error?: Record<string, unknown>
}

export interface HttpChallenge extends ChallengeAbstract {
  type: 'http-01'
  token: string
}

export interface DnsChallenge extends ChallengeAbstract {
  type: 'dns-01'
  token: string
}

export interface TlsAlpnChallenge extends ChallengeAbstract {
  type: 'tls-alpn-01'
  token: string
}

export type Challenge = HttpChallenge | DnsChallenge | TlsAlpnChallenge

/**
 * Certificate
 *
 * https://tools.ietf.org/html/rfc8555#section-7.6
 */
export enum CertificateRevocationReason {
  Unspecified = 0,
  KeyCompromise = 1,
  CACompromise = 2,
  AffiliationChanged = 3,
  Superseded = 4,
  CessationOfOperation = 5,
  CertificateHold = 6,
  RemoveFromCRL = 8,
  PrivilegeWithdrawn = 9,
  AACompromise = 10,
}

export interface CertificateRevocationRequest {
  reason?: CertificateRevocationReason
}

export interface ClientOptions {
  directoryUrl: string
  accountKey: CryptoKey
  accountUrl?: string
  externalAccountBinding?: ClientExternalAccountBindingOptions
  backoffAttempts?: number
  backoffMin?: number
  backoffMax?: number
}

export interface ClientAutoOptions {
  csr: Buffer | string | null
  challengeCreateFn: (
    authz: Authorization,
    challenge: Challenge,
    keyAuthorization: string
  ) => Promise<void>
  challengeRemoveFn: (
    authz: Authorization,
    challenge: Challenge,
    keyAuthorization: string
  ) => Promise<void>
  email?: string
  termsOfServiceAgreed?: boolean
  challengePriority?: string[]
  preferredChain?: string
}

/**
 * ACME states
 *
 * @private
 */

const validStates = ['ready', 'valid']
const pendingStates = ['pending', 'processing']
const invalidStates = ['invalid']

/**
 * Default options
 *
 * @private
 */
const defaultOpts = {
  directoryUrl: undefined,
  accountKey: undefined,
  accountUrl: null,
  externalAccountBinding: {},
  backoffAttempts: 10,
  backoffMin: 3000,
  backoffMax: 30000,
}

/**
 * AcmeClient
 *
 * @class
 * @param {object} opts
 * @param {string} opts.directoryUrl ACME directory URL
 * @param {buffer|string} opts.accountKey PEM encoded account private key
 * @param {string} [opts.accountUrl] Account URL, default: `null`
 * @param {object} [opts.externalAccountBinding]
 * @param {string} [opts.externalAccountBinding.kid] External account binding KID
 * @param {string} [opts.externalAccountBinding.hmacKey] External account binding HMAC key
 * @param {number} [opts.backoffAttempts] Maximum number of backoff attempts, default: `10`
 * @param {number} [opts.backoffMin] Minimum backoff attempt delay in milliseconds, default: `5000`
 * @param {number} [opts.backoffMax] Maximum backoff attempt delay in milliseconds, default: `30000`
 *
 * @example Create ACME client instance
 * ```js
 * const client = new acme.Client({
 *     directoryUrl: acme.directory.letsencrypt.staging,
 *     accountKey: 'Private key goes here'
 * });
 * ```
 *
 * @example Create ACME client instance
 * ```js
 * const client = new acme.Client({
 *     directoryUrl: acme.directory.letsencrypt.staging,
 *     accountKey: <'Private key goes here'>,
 *     accountUrl: 'Optional account URL goes here',
 *     backoffAttempts: 10,
 *     backoffMin: 5000,
 *     backoffMax: 30000
 * });
 * ```
 *
 * @example Create ACME client with external account binding
 * ```js
 * const client = new acme.Client({
 *     directoryUrl: 'https://acme-provider.example.com/directory-url',
 *     accountKey: 'Private key goes here',
 *     externalAccountBinding: {
 *         kid: 'YOUR-EAB-KID',
 *         hmacKey: 'YOUR-EAB-HMAC-KEY'
 *     }
 * });
 * ```
 */
export class AcmeClient {
  opts: ClientOptions
  backoffOpts: {
    attempts: number | undefined
    min: number | undefined
    max: number | undefined
  }
  api: HttpClient

  constructor(opts: ClientOptions) {
    // if (!Buffer.isBuffer(opts.accountKey)) {
    //     opts.accountKey = Buffer.from(opts.accountKey);
    // }

    this.opts = Object.assign({}, defaultOpts, opts)

    this.backoffOpts = {
      attempts: this.opts.backoffAttempts,
      min: this.opts.backoffMin,
      max: this.opts.backoffMax,
    }

    // FIXME accountKey - is a CryptoKey object not a PEM/string/Object...
    this.api = new HttpClient(
      this.opts.directoryUrl,
      this.opts.accountKey,
      this.opts.accountUrl
    )
  }

  /**
   * Get Terms of Service URL if available
   *
   * @returns {Promise<string|null>} ToS URL
   *
   * @example Get Terms of Service URL
   * ```js
   * const termsOfService = client.getTermsOfServiceUrl();
   *
   * if (!termsOfService) {
   *     // CA did not provide Terms of Service
   * }
   * ```
   */
  async getTermsOfServiceUrl(): Promise<string | undefined> {
    return this.api.getTermsOfServiceUrl()
  }

  /**
   * Get current account URL
   *
   * @returns {string} Account URL
   * @throws {Error} No account URL found
   *
   * @example Get current account URL
   * ```js
   * try {
   *     const accountUrl = client.getAccountUrl();
   * }
   * catch (e) {
   *     // No account URL exists, need to create account first
   * }
   * ```
   */
  getAccountUrl(): string {
    return this.api.getAccountUrl()
  }

  /**
   * Create a new account
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3
   *
   * @param {object} [data] Request data
   * @returns {Promise<object>} Account
   *
   * @example Create a new account
   * ```js
   * const account = await client.createAccount({
   *     termsOfServiceAgreed: true
   * });
   * ```
   *
   * @example Create a new account with contact info
   * ```js
   * const account = await client.createAccount({
   *     termsOfServiceAgreed: true,
   *     contact: ['mailto:test@example.com']
   * });
   * ```
   */
  async createAccount(
    data: AccountCreateRequest = {
      termsOfServiceAgreed: false,
    }
  ): Promise<Record<string, unknown>> {
    try {
      this.getAccountUrl()

      /* Account URL exists */
      ngx.log(ngx.INFO, 'njs-acme: [client] Account URL exists, updating it...')
      return await this.updateAccount(data)
    } catch (e) {
      const resp = await this.api.createAccount(data)

      /* HTTP 200: Account exists */
      if (resp.status === 200) {
        ngx.log(
          ngx.INFO,
          'njs-acme: [client] Account already exists (HTTP 200), updating it...'
        )
        return await this.updateAccount(data)
      }
      return (await resp.json()) as Promise<Record<string, unknown>>
    }
  }

  /**
   * Update existing account
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3.2
   *
   * @param {object} [data] Request data
   * @returns {Promise<object>} Account
   *
   * @example Update existing account
   * ```js
   * const account = await client.updateAccount({
   *     contact: ['mailto:foo@example.com']
   * });
   * ```
   */
  async updateAccount(
    data: AccountUpdateRequest = {}
  ): Promise<Record<string, unknown>> {
    try {
      this.api.getAccountUrl()
    } catch (e) {
      return this.createAccount(data || undefined)
    }

    /* Remove data only applicable to createAccount() */
    if (data && 'onlyReturnExisting' in data) {
      delete data.onlyReturnExisting
    }

    /* POST-as-GET */
    if (data && Object.keys(data).length === 0) {
      data = null
    }

    const resp = await this.api.updateAccount(data)
    return (await resp.json()) as Promise<Record<string, unknown>>
  }

  /**
   * Update account private key
   *
   * https://tools.ietf.org/html/rfc8555#section-7.3.5
   *
   * @param {CryptoKey|buffer|string} newAccountKey New account private key
   * @param {object} [data] Additional request data
   * @returns {Promise<object>} Account
   *
   * @example Update account private key
   * ```js
   * const newAccountKey = 'New private key goes here';
   * const result = await client.updateAccountKey(newAccountKey);
   * ```
   */
  async updateAccountKey(
    newAccountKey: CryptoKey | string | Buffer,
    data: Record<string, unknown> = {}
  ): Promise<Record<string, unknown>> {
    // FIXME: if string | Buffer then handle reading from PEM

    if (Buffer.isBuffer(newAccountKey) || typeof newAccountKey === 'string') {
      newAccountKey = Buffer.from(newAccountKey)
    }

    const accountUrl = this.api.getAccountUrl()

    const newCryptoKey = '' // TODO FIX THIS

    /* Create new HTTP and API clients using new key */
    const newHttpClient = new HttpClient(
      this.opts.directoryUrl,
      newCryptoKey,
      accountUrl
    )

    /* Get old JWK */
    data.account = accountUrl
    data.oldKey = this.api.getJwk()

    /* Get signed request body from new client */
    const url = await newHttpClient.getResourceUrl('keyChange')
    const body = await newHttpClient.createSignedBody(url, data)

    /* Change key using old client */
    const resp = await this.api.updateAccountKey(body)

    /* Replace existing HTTP and API client */
    this.api = newHttpClient

    // FIXME
    return (await resp.json()) as Record<string, unknown>
  }

  /**
   * Create a new order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {object} data Request data
   * @returns {Promise<object>} Order
   *
   * @example Create a new order
   * ```js
   * const order = await client.createOrder({
   *     identifiers: [
   *         { type: 'dns', value: 'example.com' },
   *         { type: 'dns', value: 'test.example.com' }
   *     ]
   * });
   * ```
   */
  async createOrder(data: OrderCreateRequest): Promise<Order> {
    const resp = await this.api.createOrder(data)

    if (!resp.headers.get('location')) {
      throw new Error('Creating a new order did not return an order link')
    }

    // FIXME
    /* Add URL to response */
    const respData = (await resp.json()) as Order
    respData.url = resp.headers.get('location')
    return respData
  }

  /**
   * Refresh order object from CA
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {object} order Order object
   * @returns {Promise<object>} Order
   *
   * @example
   * ```js
   * const order = { ... }; // Previously created order object
   * const result = await client.getOrder(order);
   * ```
   */
  async getOrder(order: Order): Promise<Record<string, unknown>> {
    if (!order.url) {
      throw new Error('Unable to get order, URL not found')
    }

    const resp = await this.api.getOrder(order.url)

    /* Add URL to response */
    const respData = (await resp.json()) as Record<string, unknown>
    respData.url = order.url
    return respData
  }

  /**
   * Finalize order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4
   *
   * @param {object} order Order object
   * @param {buffer|string} csr PEM encoded Certificate Signing Request
   * @returns {Promise<object>} Order
   *
   * @example Finalize order
   * ```js
   * const order = { ... }; // Previously created order object
   * const csr = { ... }; // Previously created Certificate Signing Request
   * const result = await client.finalizeOrder(order, csr);
   * ```
   */
  async finalizeOrder(
    order: Order,
    csr: Buffer | string
  ): Promise<Record<string, unknown>> {
    if (!order.finalize) {
      throw new Error('Unable to finalize order, URL not found')
    }

    if (!Buffer.isBuffer(csr)) {
      csr = Buffer.from(csr)
    }

    const data = { csr: getPemBodyAsB64u(csr) }
    let resp
    try {
      resp = await this.api.finalizeOrder(order.finalize, data)
    } catch (e) {
      ngx.log(ngx.WARN, `njs-acme: [client] finalize order failed: ${e}`)
      throw e
    }
    /* Add URL to response */
    const respData = (await resp.json()) as Record<string, unknown>
    respData.url = order.url
    return respData
  }

  /**
   * Get identifier authorizations from order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5
   *
   * @param {object} order Order
   * @returns {Promise<object[]>} Authorizations
   *
   * @example Get identifier authorizations
   * ```js
   * const order = { ... }; // Previously created order object
   * const authorizations = await client.getAuthorizations(order);
   *
   * authorizations.forEach((authz) => {
   *     const { challenges } = authz;
   * });
   * ```
   */
  async getAuthorizations(order: Order): Promise<Authorization[]> {
    return Promise.all(
      (order.authorizations || []).map(async (url) => {
        const resp = await this.api.getAuthorization(url)
        const respData = (await resp.json()) as Authorization
        /* Add URL to response */
        respData.url = url
        return respData
      })
    )
  }

  /**
   * Deactivate identifier authorization
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5.2
   *
   * @param {object} authz Identifier authorization
   * @returns {Promise<object>} Authorization
   *
   * @example Deactivate identifier authorization
   * ```js
   * const authz = { ... }; // Identifier authorization resolved from previously created order
   * const result = await client.deactivateAuthorization(authz);
   * ```
   */
  async deactivateAuthorization(
    authz: Authorization
  ): Promise<Record<string, unknown>> {
    if (!authz.url) {
      throw new Error(
        'Unable to deactivate identifier authorization, URL not found'
      )
    }

    const data = {
      status: 'deactivated',
    }

    const resp = await this.api.updateAuthorization(authz.url as string, data)

    /* Add URL to response */
    const respData = (await resp.json()) as Record<string, unknown>
    respData.url = authz.url
    return respData
  }

  /**
   * Get key authorization for ACME challenge
   *
   * https://tools.ietf.org/html/rfc8555#section-8.1
   *
   * @param {object} challenge Challenge object returned by API
   * @returns {Promise<string>} Key authorization
   *
   * @example Get challenge key authorization
   * ```js
   * const challenge = { ... }; // Challenge from previously resolved identifier authorization
   * const key = await client.getChallengeKeyAuthorization(challenge);
   *
   * // Write key somewhere to satisfy challenge
   * ```
   */
  async getChallengeKeyAuthorization(challenge: Challenge): Promise<string> {
    const jwk = await this.api.getJwk()

    const keysum = OGCrypto.createHash('sha256').update(JSON.stringify(jwk))
    const thumbprint = keysum.digest('base64url')
    const result = `${challenge.token}.${thumbprint}`

    /**
     * https://tools.ietf.org/html/rfc8555#section-8.3
     */
    if (challenge.type === 'http-01') {
      return result
    }

    /**
     * https://tools.ietf.org/html/rfc8555#section-8.4
     * https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01
     */
    if (challenge.type === 'dns-01' || challenge.type === 'tls-alpn-01') {
      throw new Error(`Unsupported challenge type: ${challenge.type}`)
    }

    throw new Error(
      `Unable to produce key authorization, unknown challenge type: ${challenge}`
    )
  }

  /**
   * Notify CA that challenge has been completed
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5.1
   *
   * @param {object} challenge Challenge object returned by API
   * @returns {Promise<object>} Challenge
   *
   * @example Notify CA that challenge has been completed
   * ```js
   * const challenge = { ... }; // Satisfied challenge
   * const result = await client.completeChallenge(challenge);
   * ```
   */
  async completeChallenge(
    challenge: Challenge
  ): Promise<Record<string, unknown>> {
    const resp = await this.api.completeChallenge(challenge.url as string, {})
    return (await resp.json()) as Record<string, unknown>
  }

  /**
   * Wait for ACME provider to verify status on a order, authorization or challenge
   *
   * https://tools.ietf.org/html/rfc8555#section-7.5.1
   *
   * @param {object} item An order, authorization or challenge object
   * @returns {Promise<object>} Valid order, authorization or challenge
   *
   * @example Wait for valid challenge status
   * ```js
   * const challenge = { ... };
   * await client.waitForValidStatus(challenge);
   * ```
   *
   * @example Wait for valid authoriation status
   * ```js
   * const authz = { ... };
   * await client.waitForValidStatus(authz);
   * ```
   *
   * @example Wait for valid order status
   * ```js
   * const order = { ... };
   * await client.waitForValidStatus(order);
   * ```
   */
  async waitForValidStatus(
    item: Record<string, unknown> | Challenge
  ): Promise<Record<string, unknown>> {
    if (!item.url) {
      throw new Error('Unable to verify status of item, URL not found')
    }

    const verifyFn = async (abort: () => void) => {
      const resp = await this.api.apiRequest(item.url as string, null, [200])

      /* Verify status */
      const respData = (await resp.json()) as Record<string, string>
      ngx.log(
        ngx.INFO,
        `njs-acme: [client] Item has status: ${respData.status}`
      )

      if (invalidStates.includes(respData.status)) {
        abort()
        throw new Error(formatResponseError(respData))
      } else if (pendingStates.includes(respData.status)) {
        throw new Error('Operation is pending or processing')
      } else if (validStates.includes(respData.status)) {
        return respData
      }

      throw new Error(`Unexpected item status: ${respData.status}`)
    }

    ngx.log(
      ngx.INFO,
      `njs-acme: [client] Waiting for valid status from: ${item.url} ${this.backoffOpts}`
    )
    return retry(verifyFn, this.backoffOpts) as Promise<Record<string, unknown>>
  }

  /**
   * Get certificate from ACME order
   *
   * https://tools.ietf.org/html/rfc8555#section-7.4.2
   *
   * @param {object} order Order object
   * @param {string} [preferredChain] Indicate which certificate chain is preferred if a CA offers multiple, by exact issuer common name, default: `null`
   * @returns {Promise<string>} Certificate
   *
   * @example Get certificate
   * ```js
   * const order = { ... }; // Previously created order
   * const certificate = await client.getCertificate(order);
   * ```
   *
   * @example Get certificate with preferred chain
   * ```js
   * const order = { ... }; // Previously created order
   * const certificate = await client.getCertificate(order, 'DST Root CA X3');
   * ```
   */
  async getCertificate(
    order: Record<string, unknown>,
    _preferredChain: string | null = null // TODO delete?
  ): Promise<NjsByteString> {
    if (!validStates.includes(order.status as string)) {
      order = await this.waitForValidStatus(order)
    }

    if (!order.certificate) {
      throw new Error('Unable to download certificate, URL not found')
    }

    const resp = await this.api.apiRequest(order.certificate as string, null, [
      200,
    ])

    /* Handle alternate certificate chains */
    // TODO -- SHOULD WE DELETE THIS? OR IMPLEMENT utils.*
    //if (preferredChain && resp.headers.link) {
    //  const alternateLinks = util.parseLinkHeader(resp.headers.link)
    //  const alternates = await Promise.all(
    //    alternateLinks.map(async (link: string) =>
    //      this.api.apiRequest(link, null, [200])
    //    )
    //  )
    //  const certificates = [resp].concat(alternates).map((c) => c.data)

    //  return util.findCertificateChainForIssuer(certificates, preferredChain)
    //}

    /* Return default certificate chain */
    // FIXME: is it json() or text()
    return await resp.text()
  }

  /**
   * Revoke certificate
   *
   * https://tools.ietf.org/html/rfc8555#section-7.6
   *
   * @param {buffer|string} cert PEM encoded certificate
   * @param {object} [data] Additional request data
   * @returns {Promise}
   *
   * @example Revoke certificate
   * ```js
   * const certificate = { ... }; // Previously created certificate
   * const result = await client.revokeCertificate(certificate);
   * ```
   *
   * @example Revoke certificate with reason
   * ```js
   * const certificate = { ... }; // Previously created certificate
   * const result = await client.revokeCertificate(certificate, {
   *     reason: 4
   * });
   * ```
   */
  async revokeCertificate(
    cert: Buffer | string,
    data: Record<string, unknown> = {}
  ): Promise<Record<string, unknown>> {
    data.certificate = getPemBodyAsB64u(cert)
    const resp = await this.api.revokeCert(data)
    return (await resp.json()) as Record<string, unknown>
  }

  /**
   * Auto mode
   *
   * @param {object} opts
   * @param {buffer|string} opts.csr Certificate Signing Request
   * @param {function} opts.challengeCreateFn Function returning Promise triggered before completing ACME challenge
   * @param {function} opts.challengeRemoveFn Function returning Promise triggered after completing ACME challenge
   * @param {string} [opts.email] Account email address
   * @param {boolean} [opts.termsOfServiceAgreed] Agree to Terms of Service, default: `false`
   * @param {string[]} [opts.challengePriority] Array defining challenge type priority, default: `['http-01', 'dns-01']`
   * @param {string} [opts.preferredChain] Indicate which certificate chain is preferred if a CA offers multiple, by exact issuer common name, default: `null`
   * @returns {Promise<string>} Certificate
   *
   * @example Order a certificate using auto mode
   * ```js
   * const [certificateKey, certificateRequest] = await acme.crypto.createCsr({
   *     commonName: 'test.example.com'
   * });
   *
   * const certificate = await client.auto({
   *     csr: certificateRequest,
   *     email: 'test@example.com',
   *     termsOfServiceAgreed: true,
   *     challengeCreateFn: async (authz, challenge, keyAuthorization) => {
   *         // Satisfy challenge here
   *     },
   *     challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
   *         // Clean up challenge here
   *     }
   * });
   * ```
   *
   * @example Order a certificate using auto mode with preferred chain
   * ```js
   * const [certificateKey, certificateRequest] = await acme.crypto.createCsr({
   *     commonName: 'test.example.com'
   * });
   *
   * const certificate = await client.auto({
   *     csr: certificateRequest,
   *     email: 'test@example.com',
   *     termsOfServiceAgreed: true,
   *     preferredChain: 'DST Root CA X3',
   *     challengeCreateFn: async () => {},
   *     challengeRemoveFn: async () => {}
   * });
   * ```
   */
  auto(opts: ClientAutoOptions): Promise<NjsByteString> {
    return auto(this, opts)
  }
}

const autoDefaultOpts: ClientAutoOptions = {
  csr: null,
  email: undefined,
  preferredChain: undefined,
  termsOfServiceAgreed: false,
  challengePriority: ['http-01'],
  challengeCreateFn: async () => {
    throw new Error('Missing challengeCreateFn()')
  },
  challengeRemoveFn: async () => {
    throw new Error('Missing challengeRemoveFn()')
  },
}

/**
 * ACME client auto mode
 *
 * @param {AcmeClient} client ACME client
 * @param {ClientAutoOptions} userOpts Options
 * @returns {Promise<NjsByteString>} Certificate
 */
async function auto(
  client: AcmeClient,
  userOpts: ClientAutoOptions
): Promise<NjsByteString> {
  const opts = Object.assign({}, autoDefaultOpts, userOpts)
  const accountPayload: Record<string, unknown> = {
    termsOfServiceAgreed: opts.termsOfServiceAgreed,
  }

  if (!Buffer.isBuffer(opts.csr) && opts.csr) {
    opts.csr = Buffer.from(opts.csr)
  }

  if (opts.email) {
    accountPayload.contact = [`mailto:${opts.email}`]
  }

  /**
   * Register account
   */
  ngx.log(ngx.INFO, 'njs-acme: [auto] Checking account')

  try {
    client.getAccountUrl()
    ngx.log(
      ngx.INFO,
      'njs-acme: [auto] Account URL already exists, skipping account registration'
    )
  } catch (e) {
    ngx.log(ngx.INFO, 'njs-acme: [auto] Registering account')
    await client.createAccount(accountPayload)
  }

  /**
   * Parse domains from CSR
   */
  // FIXME implement parsing CSR to get a list of domain...
  ngx.log(
    ngx.INFO,
    'njs-acme: [auto] Parsing domains from Certificate Signing Request'
  )
  // const csrDomains = readCsrDomains(opts.csr);
  // const domains = [csrDomains.commonName].concat(csrDomains.altNames);
  // const uniqueDomains = Array.from(new Set(domains));

  const uniqueDomains = ['proxy.nginx.com']
  ngx.log(
    ngx.INFO,
    `njs-acme: [auto] Resolved ${uniqueDomains.length} unique domains from parsing the Certificate Signing Request`
  )

  /**
   * Place order
   */
  const orderPayload = {
    identifiers: uniqueDomains.map((d) => ({ type: 'dns', value: d })),
  }
  const order = await client.createOrder(orderPayload)
  const authorizations = await client.getAuthorizations(order)
  ngx.log(ngx.INFO, `njs-acme: [auto] Placed certificate order successfully`)

  /**
   * Resolve and satisfy challenges
   */
  ngx.log(
    ngx.INFO,
    'njs-acme: [auto] Resolving and satisfying authorization challenges'
  )

  const challengePromises = authorizations.map(async (authz: Authorization) => {
    const d = authz.identifier?.value
    let challengeCompleted = false

    /* Skip authz that already has valid status */
    if (authz.status === 'valid') {
      ngx.log(
        ngx.INFO,
        `njs-acme: [auto] [${d}] Authorization already has valid status, no need to complete challenges`
      )
      return
    }

    try {
      /* Select challenge based on priority */
      const challenge = authz.challenges
        ?.sort((a: Challenge, b: Challenge) => {
          const aidx = opts.challengePriority?.indexOf(a.type as string) || -1
          const bidx = opts.challengePriority?.indexOf(b.type as string) || -1

          if (aidx === -1) return 1
          if (bidx === -1) return -1
          return aidx - bidx
        })
        .slice(0, 1)[0]

      if (!challenge) {
        throw new Error(
          `Unable to select challenge for ${d}, no challenge found`
        )
      }

      ngx.log(
        ngx.INFO,
        `njs-acme: [auto] [${d}] Found ${authz.challenges.length} challenges, selected type: ${challenge.type}`
      )

      /* Trigger challengeCreateFn() */
      const keyAuthorization = await client.getChallengeKeyAuthorization(
        challenge
      )

      try {
        await opts.challengeCreateFn(authz, challenge, keyAuthorization)

        /* Complete challenge and wait for valid status */
        ngx.log(
          ngx.INFO,
          `njs-acme: [auto] [${d}] Completing challenge with ACME provider and waiting for valid status`
        )
        await client.completeChallenge(challenge)
        challengeCompleted = true

        await client.waitForValidStatus(challenge)
      } finally {
        /* Trigger challengeRemoveFn(), suppress errors */
        try {
          await opts.challengeRemoveFn(authz, challenge, keyAuthorization)
        } catch (e) {
          ngx.log(
            ngx.INFO,
            `njs-acme: [auto] [${d}] challengeRemoveFn threw error: ${
              (e as Error).message
            }`
          )
        }
      }
    } catch (e: unknown) {
      /* Deactivate pending authz when unable to complete challenge */
      if (!challengeCompleted) {
        ngx.log(
          ngx.INFO,
          `njs-acme: [auto] [${d}] Unable to complete challenge: ${
            (e as Error).message
          }`
        )

        try {
          await client.deactivateAuthorization(authz)
        } catch (f: unknown) {
          /* Suppress deactivateAuthorization() errors */
          ngx.log(
            ngx.INFO,
            `njs-acme: [auto] [${d}] Authorization deactivation threw error: ${
              (f as Error).message
            }`
          )
        }
      }

      throw e
    }
  })

  ngx.log(ngx.INFO, 'njs-acme: [auto] Waiting for challenge valid status')
  await Promise.all(challengePromises)

  if (!opts.csr) {
    throw new Error('options is missing required csr')
  }

  /**
   * Finalize order and download certificate
   */
  ngx.log(ngx.INFO, 'njs-acme: [auto] Finalize order and download certificate')
  const finalized = await client.finalizeOrder(order, opts.csr)
  const certData = await client.getCertificate(finalized, opts.preferredChain)
  return certData
}
