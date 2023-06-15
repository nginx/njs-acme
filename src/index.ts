import { toPEM, readOrCreateAccountKey, generateKey, createCsr, readCertificateInfo, acmeServerNames, getVariable, joinPaths, acmeDir, acmeAccountPrivateJWKPath, acmeDirectoryURI, acmeVerifyProviderHTTPS } from './utils'
import { HttpClient } from './api'
import { AcmeClient } from './client'
import fs from 'fs';

const KEY_SUFFIX = '.key';
const CERTIFICATE_SUFFIX = '.crt';

/**
 * Using AcmeClient to create a new account. It creates an account key if it doesn't exists
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientNewAccount(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(acmeAccountPrivateJWKPath(r));
    // Create a new ACME account
    let client = new AcmeClient({
        directoryUrl: acmeDirectoryURI(r),
        accountKey: accountKey
    });
    // display more logs
    client.api.setDebug(true);
    // do not validate ACME provider cert
    client.api.setVerify(acmeVerifyProviderHTTPS(r));

    try {
        const account = await client.createAccount({
            termsOfServiceAgreed: true,
            contact: ['mailto:test@example.com']
        });
        return r.return(200, JSON.stringify(account));
    } catch (e) {
        ngx.log(ngx.ERR, `Error creating ACME account. Error=${e}`)
    }
}

/**
 *  Demonstrates an automated workflow to issue a new certificate for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest) {
    const prefix = acmeDir(r);
    const serverNames = acmeServerNames(r);

    const commonName = serverNames[0];
    const pkeyPath = joinPaths(prefix, commonName + KEY_SUFFIX);
    const csrPath = joinPaths(prefix, commonName + '.csr');
    const certPath = joinPaths(prefix, commonName + CERTIFICATE_SUFFIX);

    let email
    try {
        email = getVariable(r, 'njs_acme_account_email');
    } catch {
        return r.return(500, "Nginx variable 'njs_acme_account_email' or 'NJS_ACME_ACCOUNT_EMAIL' environment variable must be set");
    }

    let certificatePem;
    let pkeyPem;
    let renewCertificate = false;
    let certInfo;
    try {
        const certData = fs.readFileSync(certPath, 'utf8');
        const privateKeyData = fs.readFileSync(pkeyPath, 'utf8');

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
        const accountKey = await readOrCreateAccountKey(acmeAccountPrivateJWKPath(r));
        // Create a new ACME client
        let client = new AcmeClient({
            directoryUrl: acmeDirectoryURI(r),
            accountKey: accountKey
        });
        // client.api.setDebug(true);
        client.api.setVerify(acmeVerifyProviderHTTPS(r));

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
        fs.writeFileSync(csrPath, toPEM(result.pkcs10Ber, "CERTIFICATE REQUEST"));

        const privKey = await crypto.subtle.exportKey("pkcs8", result.keys.privateKey);
        pkeyPem = toPEM(privKey, "PRIVATE KEY");
        fs.writeFileSync(pkeyPath, pkeyPem);
        ngx.log(ngx.INFO, `njs-acme: [auto] Wrote Private key to ${pkeyPath}`);

        // default challengePath = acmeDir/challenge
        const challengePath = getVariable(r, 'njs_acme_challenge_dir', joinPaths(acmeDir(r), 'challenge'));
        if (challengePath === undefined || challengePath.length === 0) {
            return r.return(500, "Nginx variable 'njs_acme_challenge_dir' must be set");
        }
        ngx.log(ngx.INFO, `njs-acme: [auto] Issuing a new Certificate: ${JSON.stringify(params)}`);
        const fullChallengePath = joinPaths(challengePath, '.well-known/acme-challenge');
        try {
            fs.mkdirSync(fullChallengePath, { recursive: true });
        } catch (e) {
            ngx.log(ngx.ERR, `Error creating directory to store challenges at ${fullChallengePath}. Ensure the ${challengePath} directory is writable by the nginx user.`)
            return r.return(500, "Cannot create challenge directory");
        }

        certificatePem = await client.auto({
            csr: result.pkcs10Ber,
            email: email,
            termsOfServiceAgreed: true,
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                ngx.log(ngx.INFO, `njs-acme: [auto] Challenge Create (authz='${JSON.stringify(authz)}', challenge='${JSON.stringify(challenge)}', keyAuthorization='${keyAuthorization}')`);
                ngx.log(ngx.INFO, `njs-acme: [auto] Writing challenge file so nginx can serve it via .well-known/acme-challenge/${challenge.token}`);
                const path = joinPaths(fullChallengePath, challenge.token);
                fs.writeFileSync(path, keyAuthorization);
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                const path = joinPaths(fullChallengePath, challenge.token);
                try {
                    fs.unlinkSync(path);
                    ngx.log(ngx.INFO, `njs-acme: [auto] removed challenge ${path}`);
                } catch (e) {
                    ngx.log(ngx.ERR, `njs-acme: [auto] failed to remove challenge ${path}`);
                }
            }
        });
        certInfo = await readCertificateInfo(certificatePem);
        fs.writeFileSync(certPath, certificatePem);
        r.log(`njs-acme: wrote certificate to ${certPath}`);
    }

    const info = {
        certificate: certInfo,
        renewedCertificate: renewCertificate,
    }

    return r.return(200, JSON.stringify(info));
}


/**
 * Demonstrates how to use generate RSA Keys and use HttpClient
 * @param r
 * @returns
 */
async function acmeNewAccount(r: NginxHTTPRequest) {
    ngx.log(ngx.ERR, `VERIFY_PROVIDER_HTTPS: ${acmeVerifyProviderHTTPS(r)}`);

    /* Generate a new RSA key pair for ACME account */
    const keys = (await generateKey()) as Required<CryptoKeyPair>;

    // /* Create a new ACME account */
    let client = new HttpClient(acmeDirectoryURI(r), keys.privateKey);

    client.setDebug(true);
    client.setVerify(acmeVerifyProviderHTTPS(r));

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
 * Create a new certificate Signing Request - Example implementation
 * @param r
 * @returns
 */
async function createCsrHandler(r: NginxHTTPRequest) {
    const { pkcs10Ber, keys } = await createCsr({
        // EXAMPLE VALUES BELOW
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
 * Retrieves the cert based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string, string} - The path and cert associated with the server name.
 */
function js_cert(r: NginxHTTPRequest) {
    const prefix = acmeDir(r);
    let { path, data } = read_cert_or_key(prefix, r.variables.ssl_server_name?.toLowerCase() || '', CERTIFICATE_SUFFIX);
    // ngx.log(ngx.INFO, `njs-acme: Loaded cert for ${r.variables.ssl_server_name} from path: ${path}`);
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

/**
 * Retrieves the key based on the Nginx HTTP request.
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The path and key associated with the server name.
 */
function js_key(r: NginxHTTPRequest) {
    const prefix = acmeDir(r);
    const { path } = read_cert_or_key(prefix, r.variables.ssl_server_name?.toLowerCase() || '', KEY_SUFFIX);
    // r.log(`njs-acme: loaded key for ${r.variables.ssl_server_name} from path: ${path}`);
    return path
}

function read_cert_or_key(prefix: string, domain: string, suffix: string) {
    const none_wildcard_path = joinPaths(prefix, domain + suffix);
    const wildcard_path = joinPaths(prefix, domain.replace(/.*?\./, '*.') + suffix);

    let data = '';
    var path = '';

    try {
        data = fs.readFileSync(none_wildcard_path, 'utf8');
        path = none_wildcard_path;
    } catch (e) {
        try {
            data = fs.readFileSync(wildcard_path, 'utf8');
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
