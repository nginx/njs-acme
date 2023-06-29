# njs-acme

This repository provides a JavaScript library to work with [ACME](https://datatracker.ietf.org/doc/html/rfc8555) providers such as Let's Encrypt for **NJS**. The source code is compatible with the `ngx_http_js_module` runtime. This allows for the automatic issue of TLS/SSL certificates for NGINX.

Some ACME providers have strict rate limits. Please consult with your provider. For Let's Encrypt refer to [this](https://letsencrypt.org/docs/rate-limits/) rate-limits documentation.

This project uses Babel and Rollup to compile TypeScript sources into a single JavaScript file for `njs`. It uses Mocha with nginx-testing for running integration tests against the NGINX server. This project uses [njs-typescript-starter](https://github.com/jirutka/njs-typescript-starter/tree/master) to write NJS modules and integration tests in TypeScript.

The ACME RESTful client is implemented using [ngx.fetch](http://nginx.org/en/docs/njs/reference.html#ngx_fetch), [crypto API](http://nginx.org/en/docs/njs/reference.html#builtin_crypto), [PKI.js](https://pkijs.org/) APIs in NJS runtime.


## Configuration Variables

You can use environment variables or NGINX configuration variables to control the behavior of the NJS ACME client. In the case where both are defined, environment variables are preferred. Environment variables are in `ALL_CAPS`, whereas the nginx config variable is the same name, just `lower_case`.

### Required Variables

   - `NJS_ACME_ACCOUNT_EMAIL`\
        Your email address to send to the ACME provider.\
        value: Any valid email address\
        default: none (you must specify this!)

   - `NJS_ACME_SERVER_NAMES`\
        The hostname or list of hostnames to request the certificate for.\
        value: Space-separated list of hostnames, e.g. `www1.mydomain.com www2.mydomain.com`\
        default: none (you must specify this!)

### NGINX Variables Only (not allowed as environment variable)
   - `njs_acme_challenge_dir`\
        NGINX variable with the path to where store HTTP-01 challenges.\
        value: Any valid system path writable by the `nginx` user.\
        default: none (you must specify this!)

### Optional Variables
   - `NJS_ACME_VERIFY_PROVIDER_HTTPS`\
        Verifies the ACME provider SSL certificate when connecting.\
        value: `false` | `true`\
        default: `true`

   - `NJS_ACME_DIRECTORY_URI`\
        ACME directory URL.\
        value: Any valid URL\
        default: `https://acme-staging-v02.api.letsencrypt.org/directory`

   - `NJS_ACME_DIR`\
        Path to store ACME-related files such as keys, certificate requests, certificates, etc.\
        value: Any valid system path writable by the `nginx` user. \
        default: `/etc/acme/`

   - `NJS_ACME_ACCOUNT_PRIVATE_JWK`\
        Path to fetch/store the account private JWK.\
        value: Path to the private JWK\
        default: `${NJS_ACME_DIR}/account_private_key.json`


## NGINX Configuration

There are a few pieces that are required to be present in your `nginx.conf` file. The file at `examples/nginx.conf` shows them all.

### Config Root
* Ensures the NJS module is loaded.
   ```nginx
  load_module modules/ngx_http_js_module.so;
  ```

### `http` Section
* Adds our module directory to the search path.
  ```nginx
  js_path "/usr/lib/nginx/njs_modules/";
  ```
* Ensures the Let's Encrypt root certificate is loaded.
  ```nginx
  js_fetch_trusted_certificate /etc/ssl/certs/ISRG_Root_X1.pem;
  ```
* Load `acme.js` into the `acme` namespace.
  ```nginx
  js_import acme from acme.js;
  ```
* Configure a DNS resolver for NJS to use.
  ```nginx
  resolver 127.0.0.11 ipv6=off; # docker-compose
  ```

### `server` Section
* Set the hostname or hostnames (space-separated) to generate the certificate.
  ```nginx
  set $njs_acme_server_names proxy.nginx.com;
  ```
* Set your email address to use to configure your ACME account.
  ```nginx
  set $njs_acme_account_email test@example.com;
  ```
* Set the directory to store challenges. This is also used in a `location{}` block below.
  ```nginx
  set $njs_acme_challenge_dir /etc/acme/challenge;
  ```
* Set and use variables to hold the certificate and key paths using Javascript.
  ```nginx
  js_set $dynamic_ssl_cert acme.js_cert;
  js_set $dynamic_ssl_key acme.js_key;

  ssl_certificate $dynamic_ssl_cert;
  ssl_certificate_key $dynamic_ssl_key;
  ```
### `location` Blocks
* Location to handle ACME challenge requests. `$njs_acme_challenge_dir` is used here.
  ```nginx
  location ^~ /.well-known/acme-challenge/ {
    default_type "text/plain";
    root $njs_acme_challenge_dir;
  }
  ```
* Location, that when requested, inspects the stored certificate (if present) and will request a new certificate if necessary. The included `docker-compose.yml` shows how to use a `healthcheck:` configuration for the NGINX service to periodically request this endpoint.
    ```nginx
    location = /acme/auto {
      js_content acme.clientAutoMode;
    }
    ```

## Automatic Certificate Renewal

NGINX and NJS do not yet have a mechanism for running code on a time interval, which presents a challenge for certificate renewal. One workaround to this is to set something up to periodically request `/acme/auto` from the NGINX server. This can be done via `cron`, or if you are running in a `docker compose` context, you can use Docker's `healthcheck:` functionality to do this. Here is an example:

```docker
service:
  nginx:
    ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://proxy.nginx.com:8000/acme/auto"]
      interval: 1m30s
      timeout: 90s
      retries: 3
      start_period: 10s
```

This configuration will request `/acme/auto` every 90 seconds. If the certificate is nearing expiry, it will be automatically renewed.

## Development

### With Docker

There is a `docker-compose.yml` file in the project root directory that brings up an ACME server, a challenge server, a Node.js container for rebuilding the `acme.js` file when source files change, and an NGINX container. The built `acme.js` file is shared between the Node.js and NGINX containers. The NGINX container will reload when the `acme.js` file changes.

To start up the development environment with docker compose, run the following:

    make start-all

If you use VSCode or another devcontainer-compatible editor, then run the following:

    code .

Choose to "Reopen in container" and the services specified in the `docker-compose.yml` file will start. Editing and saving source files will trigger a rebuild of the `acme.js` file, and NGINX will reload its configuration.

### Without Docker

To follow these steps, you will need to have Node.js version 14.15 or greater installed on your system.

1. Install dependencies:

        npm ci

2. Start the watcher:

        npm run watch

3. Edit the source files. When you save a change, the watcher will rebuild `./dist/acme.js` or display errors.


## Building the `acme.js` File

### With Docker

Run this command to build an NGINX container that has the `acme.js` file and an example config loaded:

    make build-docker

You can then copy the created `acme.js` file out of the container with this command:

    make copy-docker
The `acme.js` file will then be copied into the `dist/` directory.


### Without Docker

To build `acme.js` from the TypeScript source, first ensure that you have Node.js (at least version 14.15) installed on your machine, then:

1. Install dependencies

        npm ci

1. Build it:

        npm run build

1. `./dist/acme.js`  would contain the JavaScript code


## Testing

### With Docker

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


## Build Your Own Flows

If the reference impelementation does not meet your needs, then you can build your own flows using this project as a library of convenience functions.

The `clientAutoMode` exported function is a reference implementation of the `js_content` handler.

## Project Structure

|                       Path              | Description |
| ----                                    | ------------|
| [src](src)                              | Contains your source code that will be compiled to the `dist/` directory. |
| [integration-tests](integration-tests)  | Contains your source code of tests. |

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
