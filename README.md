# njs-acme

This repository provides JavaScript library to work with [ACME](https://datatracker.ietf.org/doc/html/rfc8555) providers(such as Let's Encrypt) for **NJS**. The source code is compatible with `ngx_http_js_module` runtime. This may allow the automatic issue of certificates for NGINX.

Some ACME providers, such as Let's Encrypt have strict rate limits. Please consult with your provider. For Let's Encrypt refer to [this](https://letsencrypt.org/docs/rate-limits/) rate-limits documentation.


## Getting Started

It uses Babel and Rollup to compile TypeScript sources into a single JavaScript file for `njs` and Mocha with nginx-testing for running integration tests against the NGINX server. This project uses [njs-typescript-starter](https://github.com/jirutka/njs-typescript-starter/tree/master) to write NJS modules and integration tests in TypeScript.

To build a JavaScript code From TypeScript:

1. Install dependencies

        npm install

1. Build it:

        npm run build

1. `./dist/main.js`  would contain the JavaScript code


Here are some steps to test it via Docker:

1. Start a test environment in Docker:

        make start-all

2. Optionally you can watch for `nginx` log file in a separate shell:

        docker compose logs -f nginx

3. When started initially, nginx would not have certificates at all (/etc/letsencrypt/), so we can issue a new one by sending an HTTP request to a location with `js_content` handler:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/acme/auto

4. Send an HTTP request to nginx running in Docker:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/

5. Send an HTTPS request to nginx running in Docker to test a new certificate:

        curl -vik --resolve proxy.nginx.com:4443:127.0.0.1 https://proxy.nginx.com:4443

6. Test with `openssl`:

        openssl s_client -servername proxy.nginx.com -connect localhost:4443 -showcerts

7. Display content of certificates

        docker compose exec -it nginx ls -la /etc/letsencrypt/

[Docker-compose](./docker-compose.yml) file uses volumes to persist artifacts (account keys, certificate, keys). Additionally, [letsencrypt/pebble](https://github.com/letsencrypt/pebble) is used for testing in Docker, so you don't need to open up port 80 for challenge validation.

## Project Structure

|                       Path              | Description |
| ----                                    | ------------|
| [src](src)                              | Contains your source code that will be compiled to the `dist/` directory. |
| [integration-tests](integration-tests)  | Contains your source code of tests. |

## How to Use

This library implements ACME RESTful client using [ngx.fetch](http://nginx.org/en/docs/njs/reference.html#ngx_fetch), [crypto API](http://nginx.org/en/docs/njs/reference.html#builtin_crypto), [PKI.js](https://pkijs.org/) APIs in NJS runtime. This allows using this ACME Client as a library to implement your flows. Such as within a handler for `js_content`:

The `clientAutoMode` exported function is a reference implementation of the `js_content` handler.

This implementation uses the following env variables:

   - `NJS_ACME_VERIFY_PROVIDER_HTTPS` sets verify ACME provider SSL certificate when connecting to it, default value `true`;
   - `NJS_ACME_DIRECTORY_URI` ACME directory URL, default value `https://acme-staging-v02.api.letsencrypt.org/directory`
   - `NJS_ACME_DIR` (or `njs_acme_dir` nginx variable)  default value `/etc/nginx`
   - `NJS_ACME_ACCOUNT_EMAIL` (`njs_acme_account_email`) - email address for ACME provider
   - `njs_acme_challenge_dir` - nginx variable with the path to where store HTTP-01 challenges
   - `server_name` or `njs_acme_server_name` - nginx variable with the value of Subject Name for a certificate to issue


```TypeScript
/**
 *  Demonstrates an automated workflow to issue a new certificate for `r.variables.server_name`
 *
 * @param {NginxHTTPRequest} r Incoming request
 * @returns void
 */
async function clientAutoMode(r: NginxHTTPRequest) {
    const accountKey = await readOrCreateAccountKey(NJS_ACME_ACCOUNT_PRIVATE_JWK);
    // /* Create a new ACME account */
    let client = new AcmeClient({
        directoryUrl: DIRECTORY_URL,
        accountKey: accountKey
    });
    // client.api.setDebug(true);
    client.api.setVerify(false);
    const email = r.variables.njs_acme_account_email || process.env.NJS_ACME_ACCOUNT_EMAIL
    if (email.length == 0) {
        r.return(500,"Nginx variable 'njs_acme_account_email' or 'NJS_ACME_ACCOUNT_EMAIL' environment variable must be set")
    }
    // create a new CSR
    const commonName = r.variables.server_name?.toLowerCase() || r.variables.njs_acme_server_name

    const params = {
        altNames: [commonName],
        commonName: commonName,
        // state: "WA",
        // country: "US",
        // organizationUnit: "NGINX",
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

    const challengePath = r.variables.njs_acme_challenge_dir!;
    if (challengePath === undefined || challengePath.length == 0) {
        r.return(500,"Nginx variable 'njs_acme_challenge_dir' must be set");
    }
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
```

## Contributing

Please see the [contributing guide](https://github.com/nginxinc/njs-acme-experemental/blob/main/CONTRIBUTING.md) for guidelines on how to best contribute to this project.

## License

[Apache License, Version 2.0](https://github.com/nginxinc/njs-acme-experemental/blob/main/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2023
