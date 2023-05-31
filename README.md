# njs-acme

This repository provides JavaScript library to work with [ACME](https://datatracker.ietf.org/doc/html/rfc8555) providers(such as Let's Encrypt) for **NJS**. The source code is compatible with `ngx_http_js_module` runtime. This may allow the automatic issue of certificates for NGINX.

Some ACME providers, such as Let's Encrypt have strict rate limits. Please consult with your provider. For Let's Encrypt refer to [this](https://letsencrypt.org/docs/rate-limits/) rate-limits documentation.


## Getting Started

It uses Babel and Rollup to compile TypeScript sources into a single JavaScript file for `njs` and Mocha with nginx-testing for running integration tests against the NGINX server. This project uses [njs-typescript-starter](https://github.com/jirutka/njs-typescript-starter/tree/master) to write NJS modules and integration tests in TypeScript.

Here are some steps to test it via Docker:

1. Start a test environment in Docker:

        make start-all

1. Optionally you can watch for `nginx` log file in a separate shell:

        docker compose logs -f nginx

1. When started initially, nginx would not have certificates at all (/etc/letsencrypt/), so we can issue a new one by sending an HTTP request to a location with `js_content` handler:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/acme/auto

1. Send an HTTP request to nginx running in Docker:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/

1. Send an HTTPS request to nginx running in Docker to test a new certificate:

        curl -vik --resolve proxy.nginx.com:4443:127.0.0.1 https://proxy.nginx.com:4443

1. Test with `openssl`:

        openssl s_client -servername proxy.nginx.com -connect localhost:4443 -showcerts

1. Display content of certificates

    docker compose exec -it nginx ls -la /etc/letsencrypt/

[docker-compose](./docker-compose.yml) uses volumes to persist artifacts (account keys, certificate, keys). Also, [letsencrypt/pebble](https://github.com/letsencrypt/pebble) is used for testing in Docker, so you don't really need to open up port 80 for challenge validation

## Project Structure

|                       Path              | Description |
| ----                                    | ------------|
| [src](src)                              | Contains your source code that will be compiled to the `dist/` directory. |
| [integration-tests](integration-tests)  | Contains your source code of tests. |

## How to Use

This library implements ACME RESTful client using [ngx.fetch](http://nginx.org/en/docs/njs/reference.html#ngx_fetch), [crypto API](http://nginx.org/en/docs/njs/reference.html#builtin_crypto), [PKI.js](https://pkijs.org/) APIs in NJS runtime. This allows using this ACME Client as a library to implement your flows. Such as witing a handler for `js_content`:


```TypeScript
/**
 *  Demonstrates an automated workflow to issue new certificates for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(process.env.NJS_ACME_ACCOUNT_PRIVATE_JWK || '/etc/letsencrypt/account_private_key.json');
    /* Create a new client */
    let client = new AcmeClient({
        directoryUrl: process.env.ACME_DIRECTORY_URI || 'https://pebble/dir',
        accountKey: accountKey
    });
    // we can enable more logs
    // client.api.setDebug(true);
    // don't verify Server Certificate of ACME provider, Comment/remove for Production
    client.api.setVerify(false);

    // use the same email for the Account and in the CSR
    const email = process.env.NJS_ACME_ACCOUNT_EMAIL || 'test@example.com'

    // create a new CSR
    const commonName = r.variables.server_name?.toLowerCase()
    const params = {
        altNames: [commonName],
        commonName: commonName,
        state: "WA",
        country: "US",
        organizationUnit: "CORP",
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
            const path = `${challengePath}/.well-known/acme-challenge/${challenge.token}`;
            ngx.log(ngx.INFO, `njs-acme: [auto] Writing challenge file to ${path}`);
            // Write to a FileSystem so NGINX can server it and ACME provider can validate it
            fs.writeFileSync(path, keyAuthorization, 'utf8');
        },
        challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
            const path = `${challengePath}/.well-known/acme-challenge/${challenge.token}`;
            try {
                fs.unlinkSync(path);
                ngx.log(ngx.INFO, `njs-acme: [auto] removed challenge file ${path}`);
            } catch (e) {
                ngx.log(ngx.ERR, `njs-acme: [auto] failed to remove challenge file ${path}`);
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
```

## Contributing

Please see the [contributing guide](https://github.com/nginxinc/njs-acme-experemental/blob/main/CONTRIBUTING.md) for guidelines on how to best contribute to this project.

## License

[Apache License, Version 2.0](https://github.com/nginxinc/njs-acme-experemental/blob/main/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2023
