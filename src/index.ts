import { toPEM, readOrCreateAccountKey, generateKey, createCsr, readCertificateInfo, splitPemChain, pemToBuffer, readCsrDomainNames } from './utils'
import { HttpClient, directories } from './api'
import { AcmeClient } from './client'
var fs = require('fs');

const KEY_SUFFIX = '.key';
const CERTIFICATE_SUFFIX = '.crt';
const ACCOUNT_JWK_FILENAME = process.env.NJS_ACME_ACCOUNT_JWK_FILENAME || 'account_private_key.json'
const NJS_ACME_DIR = process.env.NJS_ACME_DIR || ngx.conf_prefix;
const NJS_ACME_ACCOUNT_PRIVATE_JWK = process.env.NJS_ACME_ACCOUNT_PRIVATE_JWK || NJS_ACME_DIR + '/' + ACCOUNT_JWK_FILENAME
const DIRECTORY_URL = process.env.NJS_ACME_DIRECTORY_URI || 'https://acme-staging-v02.api.letsencrypt.org/directory'
const VERIFY_PROVIDER_HTTPS = stringToBoolean(process.env.NJS_ACME_VERIFY_PROVIDER_HTTPS, true);

function stringToBoolean(stringValue: String, val = false) {
    switch (stringValue?.toLowerCase()?.trim()) {
        case "true":
        case "yes":
        case "1":
            return true;

        case "false":
        case "no":
        case "0":
            return false;
        case null:
        case undefined:
            return val;

        default:
            return val;
    }
}


/**
 * Using AcmeClient to create a new account. It creates an account key if it doesn't exists
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientNewAccount(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(NJS_ACME_ACCOUNT_PRIVATE_JWK);
    // /* Create a new ACME account */
    let client = new AcmeClient({
        directoryUrl: DIRECTORY_URL,
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
 *  Demonstrates an automated workflow to issue a new certificate for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest) {
    const prefix = r.variables.njs_acme_dir || NJS_ACME_DIR;
    const commonName = r.variables.server_name?.toLowerCase() || r.variables.njs_acme_server_name;
    const pkeyPath = prefix + commonName + KEY_SUFFIX;
    const csrPath = prefix + commonName + '.csr';
    const certPath = prefix + commonName + CERTIFICATE_SUFFIX;

    const email = r.variables.njs_acme_account_email || process.env.NJS_ACME_ACCOUNT_EMAIL;
    if (email.length === 0) {
        r.return(500, "Nginx variable 'njs_acme_account_email' or 'NJS_ACME_ACCOUNT_EMAIL' environment variable must be set");
    }

    let certificatePem;
    let pkeyPem;
    let renewCertificate = false;
    let certInfo;
    try {
        const certData = fs.readFileSync(certPath, 'utf-8');
        const privateKeyData = fs.readFileSync(pkeyPath, 'utf-8');

        certInfo = await readCertificateInfo(certData);
        // Calculate the date 30 days before the certificate expiration
        const renewalThreshold = new Date(certInfo.notAfter);
        renewalThreshold.setDate(renewalThreshold.getDate() - 30);

        const currentDate = new Date();
        if (currentDate > renewalThreshold) {
            renewCertificate = true;
        } else {
            certificatePem = certData;
            pkeyPem = privateKeyData;
        }
    } catch {
        renewCertificate = true;
    }

    if (renewCertificate) {
        const accountKey = await readOrCreateAccountKey(NJS_ACME_ACCOUNT_PRIVATE_JWK);
        // Create a new ACME client
        let client = new AcmeClient({
            directoryUrl: DIRECTORY_URL,
            accountKey: accountKey
        });
        // client.api.setDebug(true);
        client.api.setVerify(false);

        // Create a new CSR
        const params = {
            altNames: [commonName],
            commonName: commonName,
            // state: "WA",
            // country: "US",
            // organizationUnit: "NGINX",
            emailAddress: email,
        }

        const result = await createCsr(params);
        fs.writeFileSync(csrPath, toPEM(result.pkcs10Ber, "CERTIFICATE REQUEST"), 'utf-8');
        const privKey = await crypto.subtle.exportKey("pkcs8", result.keys.privateKey);
        pkeyPem = toPEM(privKey, "PRIVATE KEY");
        fs.writeFileSync(pkeyPath, pkeyPem, 'utf-8');
        r.log(`njs-acme: [auto] Wrote Private key to ${pkeyPath}`);

        const challengePath = r.variables.njs_acme_challenge_dir!;
        if (challengePath === undefined || challengePath.length === 0) {
            r.return(500, "Nginx variable 'njs_acme_challenge_dir' must be set");
        }
        r.log(`njs-acme: [auto] Issuing a new Certificate: ${JSON.stringify(params)}`);

        certificatePem = await client.auto({
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
        certInfo = await readCertificateInfo(certificatePem);
        fs.writeFileSync(certPath, certificatePem, 'utf-8');
        r.log(`njs-acme: wrote certificate to ${certPath}`);
    }

    const info = {
        certificate: certInfo,
        renewedCertificate: renewCertificate,
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

    ngx.log(ngx.ERR, `process.env.NJS_ACME_VERIFY_PROVIDER_HTTPS: ${process.env.NJS_ACME_VERIFY_PROVIDER_HTTPS}`);
    ngx.log(ngx.ERR, `VERIFY_PROVIDER_HTTPS: ${VERIFY_PROVIDER_HTTPS}`);




    /* Generate a new RSA key pair for ACME account */
    const keys = (await generateKey()) as Required<CryptoKeyPair>;

    // /* Create a new ACME account */
    let client = new HttpClient(DIRECTORY_URL, keys.privateKey);

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
    createCsrHandler
}
