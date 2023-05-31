import { toPEM, readOrCreateAccountKey, generateKey, createCsr, readCertificateInfo, splitPemChain, pemToBuffer, readCsrDomainNames } from './utils'
import { HttpClient, directories } from './api'
import { AcmeClient } from './client'
var fs = require('fs');

const KEY_SUFFIX = '.key';
const CERTIFICATE_SUFFIX = '.crt';
const ACCOUNT_JWK_FILENAME = process.env.NJS_ACME_ACCOUNT_JWK_FILENAME || 'account_private_key.json'
const NJS_ACME_DIR = process.env.NJS_ACME_DIR || ngx.conf_prefix;
const NJS_ACME_ACCOUNT_PRIVATE_JWK = process.env.NJS_ACME_ACCOUNT_PRIVATE_JWK || NJS_ACME_DIR + '/' + ACCOUNT_JWK_FILENAME

/**
 * Using AcmeClient to create a new account. It creates an account key if it doesn't exists
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientNewAccount(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(NJS_ACME_ACCOUNT_PRIVATE_JWK);
    // /* Create a new ACME account */
    let client = new AcmeClient({
        directoryUrl: process.env.ACME_DIRECTORY_URI || 'https://pebble/dir',
        accountKey: accountKey
    });
    // display more logs
    client.api.setDebug(true);
    // do not validate ACME provider cert
    client.api.setVerify(false);

    const account = await client.createAccount({
        termsOfServiceAgreed: true,
        contact: ['mailto:test@example.com']
    });
    return r.return(200, JSON.stringify(account));
}

/**
 *  Demonstrates an automated workflow to issue new certificates for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(NJS_ACME_ACCOUNT_PRIVATE_JWK);
    // /* Create a new ACME account */
    let client = new AcmeClient({
        directoryUrl: process.env.ACME_DIRECTORY_URI || 'https://pebble/dir',
        accountKey: accountKey
    });
    // client.api.setDebug(true);
    client.api.setVerify(false);
    const email = 'test@example.com'
    // create a new CSR
    const commonName = r.variables.server_name?.toLowerCase()
    const params = {
        // altNames: ["proxy1.f5.com", "proxy2.f5.com"],
        commonName: commonName,
        state: "WA",
        country: "US",
        organizationUnit: "NGINX",
        emailAddress: email,
    }

    const result = await createCsr(params);
    const pemExported = toPEM(result.pkcs10Ber, "CERTIFICATE REQUEST");

    r.log(`njs-acme: [auto] Issuing a new Certificate: ${JSON.stringify(params)}`);

    const prefix = r.variables.njs_acme_dir || NJS_ACME_DIR;

    const privKey = await crypto.subtle.exportKey("pkcs8", result.keys.privateKey);
    const pkeyPath = prefix + commonName + KEY_SUFFIX;
    const pkeyPem = toPEM(privKey, "PRIVATE KEY");
    fs.writeFileSync(pkeyPath, pkeyPem, 'utf-8');
    r.log(`njs-acme: [auto] Wrote Private key to ${pkeyPath}`);

    const challengePath = r.variables.njs_acme_challenge_dir || ngx.conf_prefix + "/" + "html";
    const certificatePem = await client.auto({
        csr: result.pkcs10Ber,
        email: email,
        termsOfServiceAgreed: true,
        challengeCreateFn: async (authz, challenge, keyAuthorization) => {
            ngx.log(ngx.INFO, `njs-acme: [auto] Challenge Create (authz='${JSON.stringify(authz)}', challenge='${JSON.stringify(challenge)}', keyAuthorization='${keyAuthorization}')`);
            ngx.log(ngx.INFO, `njs-acme: [auto] Writing challenge file so nginx can serve it via .well-known/acme-challenge/${challenge.token}`);
            const path = `${challengePath}/.well-known/acme-challenge/${challenge.token}`;
            fs.writeFileSync(path, keyAuthorization, 'utf8');
        },
        challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
            const path = `${challengePath}/.well-known/acme-challenge/${challenge.token}`;
            try {
                fs.unlinkSync(path);
                ngx.log(ngx.INFO, `njs-acme: [auto] removed challenge ${path}`);
            } catch (e) {
                ngx.log(ngx.ERR, `njs-acme: [auto] failed to remove challenge ${path}`);
            }
        }
    });

    const certPath = prefix + commonName + CERTIFICATE_SUFFIX;
    fs.writeFileSync(certPath, certificatePem, 'utf-8');
    r.log(`njs-acme: wrote certificate to ${certPath}`);

    const info = {
        certificate: certificatePem,
        certificateKey: pkeyPem,
        csr: pemExported
    }
    return r.return(200, JSON.stringify(info));
}

async function persistGeneratedKeys(keys: CryptoKeyPair) {
    crypto.subtle.exportKey("pkcs8", keys.privateKey).then(key => {
        const pemExported = toPEM(key as ArrayBuffer, "PRIVATE KEY");
        fs.writeFileSync(NJS_ACME_DIR + "/account.private.key", pemExported, 'utf8');
    });
    crypto.subtle.exportKey("spki", keys.publicKey).then(key => {
        const pemExported = toPEM(key as ArrayBuffer, "PUBLIC KEY");
        fs.writeFileSync(NJS_ACME_DIR + "/account.public.key", pemExported, 'utf8');
    });
    crypto.subtle.exportKey("jwk", keys.privateKey).then(key => {
        fs.writeFileSync(NJS_ACME_DIR + "/account.private.json", JSON.stringify(key), 'utf8');
    });
    crypto.subtle.exportKey("jwk", keys.publicKey).then(key => {
        fs.writeFileSync(NJS_ACME_DIR + "/account.public.json", JSON.stringify(key), 'utf8');
    });
}

/**
 * Demonstrates how to use generate RSA Keys and use HttpClient
 * @param r
 * @returns
 */
async function acmeNewAccount(r: NginxHTTPRequest) {
    /* Generate a new RSA key pair for ACME account */
    const keys = (await generateKey()) as Required<CryptoKeyPair>;

    // /* Create a new ACME account */
    let client = new HttpClient(process.env.ACME_DIRECTORY_URI || 'https://pebble/dir', keys.privateKey);

    client.setDebug(true);
    client.setVerify(false);

    // Get Terms Of Service link from the ACME provider
    let tos = await client.getMetaField("termsOfService");
    ngx.log(ngx.INFO, `termsOfService: ${tos}`);
    // obtain a resource URL
    const resourceUrl: string = await client.getResourceUrl('newAccount');
    const payload = {
        termsOfServiceAgreed: true,
        contact: ['mailto:test@example.com']
    };
    // sends a signed request
    let sresp = await client.signedRequest(resourceUrl, payload);

    let respO = {
        "headers": sresp.headers,
        "data": await sresp.json(),
        "status": sresp.status,
    };
    return r.return(200, JSON.stringify(respO));
}

/**
 * Create a new certificate Signing Request
 * @param r
 * @returns
 */
async function createCsrHandler(r: NginxHTTPRequest) {
    const { pkcs10Ber, keys } = await createCsr({
        altNames: ["proxy1.f5.com", "proxy2.f5.com"],
        commonName: "proxy.f5.com",
        state: "WA",
        country: "US",
        organizationUnit: "NGINX"
    });
    const privkey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
    const pubkey = await crypto.subtle.exportKey("spki", keys.publicKey);
    const privkeyPem = toPEM(privkey, "PRIVATE KEY");
    const pubkeyPem = toPEM(pubkey, "PUBLIC KEY");
    const csrPem = toPEM(pkcs10Ber, "CERTIFICATE REQUEST");
    const result = `${privkeyPem}\n${pubkeyPem}\n${csrPem}`
    return r.return(200, result);
}

/**
 * request handler that returns subjectName and Alternative Domain names for the CSR
 * @param r
 * @returns
 */
function csrDomainNameHandler(r: NginxHTTPRequest) {
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
        "MIIC5DCCAc4CAQAwSTFHMAkGA1UEBhMCVVMwCQYDVQQIDAJXQTAJBgNVBAoMAkY1\n" +
        "MAwGA1UECwwFTkdJTlgwFgYDVQQDDA9wcm94eS5uZ2lueC5jb20wggEiMA0GCSqG\n" +
        "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqPGkd5mmin4xf6Cq7w0yabF4Cu3720PB9\n" +
        "efRk/oXLdM55vA7PccP1IrNmhc8N8GmmFk6PLyNxrDsXnD/gL+LpMIeN4smC40PE\n" +
        "2rkTfVaaux2DmDWPREFBeUzG/mTozWIbjQUQDRuVJS6HKhtjUAuWkSkTIWFUBI+t\n" +
        "dN1l0NM51xbPBBG+FjUQfJB8oXBTBhi4GW3cuNSiyJG6ovgp5pEKXXOpAhxmHoY7\n" +
        "c3rtRdL4CEkbQUB4Eroi9HMMj5/W09stR5jH7yQ2TfnFAwoo5/0C3tekzF+U9qUB\n" +
        "6pk4CfvGl6FetOfgZrNsNAlx1tMF0O4ivCmqzyj7RpRXdsZj0wQRAgMBAAGgWDBW\n" +
        "BgkqhkiG9w0BCQ4xSTBHMCkGA1UdDgQiBCCFZ8rs5phpBf85deQExG0ZHtsmdb/c\n" +
        "GR6OeyjMlZLKSTAaBgNVHREEEzARgg9wcm94eS5uZ2lueC5jb20wCwYJKoZIhvcN\n" +
        "AQELA4IBAQAUOm4vlNEjQqerZUUCzWSDWFdoqJndlvP/W9jHXlfhN8TzuxTa3Kpw\n" +
        "gTAi1g7C9aXG5VRRbjsBlQdd4ZiCJb25p1ZNkoCxBtZkKx0iSpc6NMQtMEp4vqs2\n" +
        "8qYBMrgmkgJDKxdSW5VNy+iwgBFo9lGbi39Z4FW1H0CPsWJFMDv9hZ4MO1KDZj52\n" +
        "RSAVfEL9llhTTAHfVtE8S/w83bY4vW4YP/T9xaIIo6FGXym9zAdCuuLIGwWnJZHY\n" +
        "s1djC/Y7I/4PzRFSA7I4nVCRemCXL87UBlAtnzfQUJtqZJG5CrLAu6iVyUcR518e\n" +
        "Pj5TnxWscSvixbcNWmlz586M2cj9xYrn\n" +
        "-----END CERTIFICATE REQUEST-----\n"
    const result = readCsrDomainNames(csr);
    return r.return(200, JSON.stringify(result));
}


/** Retrieves the cert based on the Nginx HTTP request.
*
* @param {NginxHTTPRequest} r - The Nginx HTTP request object.
* @returns {string, string} - The path and cert associated with the server name.
*/
function js_cert(r: NginxHTTPRequest) {
    const prefix = r.variables.njs_acme_dir || NJS_ACME_DIR;
    let { path, data } = read_cert_or_key(prefix, r.variables.ssl_server_name?.toLowerCase() || '', CERTIFICATE_SUFFIX);
    // r.log(`njs-acme: Loaded cert for ${r.variables.ssl_server_name} from path: ${path}`);
    if (data.length == 0) {
        r.log(`njs-acme: seems there is no cert for ${r.variables.ssl_server_name} from path: ${path}`);
        /*
        // FIXME: is there a way to send a subrequest so we kick in auto mode to issue a new one?
        r.subrequest('http://localhost:8000/acme/auto',
            {detached: true, method: 'GET', body: undefined});
        r.log(`njs-acme: notified /acme/auto`);

        */
    }
    return path;
}

/** Retrieves the key based on the Nginx HTTP request.
*
* @param {NginxHTTPRequest} r - The Nginx HTTP request object.
* @returns {string} - The path and key associated with the server name.
*/
function js_key(r: NginxHTTPRequest) {
    const prefix = r.variables.njs_acme_dir || NJS_ACME_DIR;
    let { path, data } = read_cert_or_key(prefix, r.variables.ssl_server_name?.toLowerCase() || '', KEY_SUFFIX);
    // r.log(`njs-acme: loaded key for ${r.variables.ssl_server_name} from path: ${path}`);
    return path
}

function read_cert_or_key(prefix: string, domain: string, suffix: string) {
    var none_wildcard_path = String.prototype.concat(prefix, domain, suffix);
    var wildcard_path = String.prototype.concat(prefix, domain.replace(/.*?\./, '*.'), suffix);
    var data = '';

    var path = '';
    try {
        data = fs.readFileSync(none_wildcard_path);
        path = none_wildcard_path;
    } catch (e) {
        try {
            data = fs.readFileSync(wildcard_path);
            path = wildcard_path;
        } catch (e) {
            data = '';
        }
    }
    return { path, data };
}

export default {
    js_cert,
    js_key,
    acmeNewAccount,
    clientNewAccount,
    clientAutoMode,
    createCsrHandler,
    csrDomainNameHandler
}
