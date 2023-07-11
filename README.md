# njs-acme

This repository provides a JavaScript library to work with [ACME](https://datatracker.ietf.org/doc/html/rfc8555) providers such as Let's Encrypt for [NJS](https://nginx.org/en/docs/njs/). The source code is compatible with the `ngx_http_js_module` runtime. This allows for the automatic issue of TLS/SSL certificates for NGINX.

Requires at least `njs-0.7.12`, which is included with NGINX since nginx-1.24.0.

NOTE: Some ACME providers have strict rate limits. Please consult with your provider. For Let's Encrypt refer to their [rate-limits documentation](https://letsencrypt.org/docs/rate-limits/).


## Configuration Variables

You can use environment variables or NGINX configuration variables to control the behavior of the NJS ACME client. In the case where both are defined, environment variables take precedence. Environment variables are in `ALL_CAPS`, whereas the nginx config variable is the same name, just `lower_case`.

### Required Variables

   - `NJS_ACME_ACCOUNT_EMAIL`\
        Your email address to send to the ACME provider.\
        value: Any valid email address\
        default: none (you must specify this!)

   - `NJS_ACME_SERVER_NAMES`\
        The hostname or list of hostnames to request the certificate for.\
        value: Space-separated list of hostnames, e.g. `www1.mydomain.com www2.mydomain.com`\
        default: none (you must specify this!)

### Optional Variables
   - `NJS_ACME_VERIFY_PROVIDER_HTTPS`\
        Verify the ACME provider certificate when connecting.\
        value: `false` | `true`\
        default: `true`

   - `NJS_ACME_DIRECTORY_URI`\
        ACME directory URL.\
        value: Any valid URL\
        default: `https://acme-staging-v02.api.letsencrypt.org/directory`

   - `NJS_ACME_DIR`\
        Path to store ACME-related files such as keys, certificate requests, certificates, etc.\
        value: Any valid system path writable by the `nginx` user. \
        default: `/etc/nginx/njs-acme/`

   - `NJS_ACME_CHALLENGE_DIR`\
        Path to store ACME-related challenge responses.\
        value: Any valid system path writable by the `nginx` user. \
        default: `${NJS_ACME_DIR}/challenge/`

   - `NJS_ACME_ACCOUNT_PRIVATE_JWK`\
        Path to fetch/store the account private JWK.\
        value: Path to the private JWK\
        default: `${NJS_ACME_DIR}/account_private_key.json`


## NGINX Configuration

There are a few pieces that are required to be present in your `nginx.conf` file. The file at [`examples/nginx.conf`](./examples/nginx.conf) shows them all.

### Config Root
* Ensures the NJS module is loaded.
   ```nginx
  load_module modules/ngx_http_js_module.so;
  ```

### `http` Section
* Adds the NJS module directory to the search path.
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
This may also be defined with the environment variable `NJS_ACME_SERVER_NAMES`.
  ```nginx
  js_var $njs_acme_server_names proxy.nginx.com;
  ```
* Set your email address to use to configure your ACME account. This may also
be defined with the environment variable `NJS_ACME_ACCOUNT_EMAIL`.
  ```nginx
  js_var $njs_acme_account_email test@example.com;
  ```
* Set and use variables to hold the certificate and key paths using Javascript.
  ```nginx
  js_set $dynamic_ssl_cert acme.js_cert;
  js_set $dynamic_ssl_key acme.js_key;

  ssl_certificate $dynamic_ssl_cert;
  ssl_certificate_key $dynamic_ssl_key;
  ```
### `location` Blocks
* Location to handle ACME challenge requests.
  ```nginx
  location ~ "^/\.well-known/acme-challenge/[-_A-Za-z0-9]{22,128}$" {
    js_content acme.challengeResponse;
  }
  ```

* Location, that when requested, inspects the stored certificate (if present) and will request a new certificate if necessary. The included `docker-compose.yml` shows how to use a `healthcheck:` configuration for the NGINX service to periodically request this endpoint.
    ```nginx
    location = /acme/auto {
      js_content acme.clientAutoMode;
    }
    ```

## Automatic Certificate Renewal

NGINX and NJS do not yet have a mechanism for running code on a time interval, which presents a challenge for certificate renewal. One workaround to this is to set something up to periodically request `/acme/auto` from the NGINX server.

If running directly on a host, you can use `cron` to schedule a periodic request. When deploying in Kubernetes you can use a [liveness-check](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-liveness-http-request). If you are running in a `docker` context, you can use Docker's `healthcheck:` functionality to do this.

Here is an example using `docker compose`:

```docker
service:
  nginx:
    ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://proxy.nginx.com:8000/acme/auto"]
      interval: 90s
      timeout: 90s
      retries: 3
      start_period: 10s
```

This configuration will request `/acme/auto` every 90 seconds. If the certificate is nearing expiry, it will be automatically renewed.

## Advanced
### Serving challenges directly
  If you do not wish to use `js_content acme.challengeResponse` to respond to challenge requests, then you can serve them directly with NGINX. Just be sure that the `root` directive value in your location block matches the value of `$njs_acme_challenge_dir`.

  ```nginx
  server {
    js_var $njs_acme_challenge_dir /etc/nginx/njs-acme/challenge;
    <...>
    location ~ "^/\.well-known/acme-challenge/[-_A-Za-z0-9]{22,128}$" {
      default_type "text/plain";
      root /etc/nginx/njs-acme/challenge/;
    }

  ```

## Development

This project uses Babel and Rollup to compile TypeScript sources into a single JavaScript file for `njs`. It uses Mocha with nginx-testing for running integration tests against the NGINX server. This project uses [njs-typescript-starter](https://github.com/jirutka/njs-typescript-starter/tree/master) to write NJS modules and integration tests in TypeScript.

The ACME RESTful client is implemented using [ngx.fetch](http://nginx.org/en/docs/njs/reference.html#ngx_fetch), [crypto API](http://nginx.org/en/docs/njs/reference.html#builtin_crypto), [PKI.js](https://pkijs.org/) APIs in the NJS runtime.

### With Docker

There is a `docker-compose.yml` file in the project root directory that brings up an ACME server, a challenge server, a Node.js container for rebuilding the `acme.js` file when source files change, and an NGINX container. The built `acme.js` file is shared between the Node.js and NGINX containers. The NGINX container will reload when the `acme.js` file changes.

To start up the development environment with docker compose, run the following:

    make docker-devup

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

    make docker-build

You can then copy the created `acme.js` file out of the container with this command:

    make docker-copy
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

        make docker-devup

2. Optionally you can watch for `nginx` log file in a separate shell:

        docker compose logs -f nginx

3. When started initially, nginx would not have certificates at all (`$njs_acme_dir`, e.g. `/etc/nginx/njs-acme/`), so we can issue a new one by sending an HTTP request to a location with the `js_content` handler:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/acme/auto

4. Send an HTTP request to nginx running in Docker:

        curl -vik --resolve proxy.nginx.com:8000:127.0.0.1 http://proxy.nginx.com:8000/

5. Send an HTTPS request to nginx running in Docker to test a new certificate:

        curl -vik --resolve proxy.nginx.com:4443:127.0.0.1 https://proxy.nginx.com:4443

6. Test with `openssl`:

        openssl s_client -servername proxy.nginx.com -connect localhost:4443 -showcerts

7. Display content of certificates

        docker compose exec -it nginx ls -la /etc/nginx/njs-acme/

The [docker-compose](./docker-compose.yml) file uses volumes to persist artifacts (account keys, certificate, keys). Additionally, [letsencrypt/pebble](https://github.com/letsencrypt/pebble) is used for testing in Docker, so you don't need to open up port 80 for challenge validation.


## Build Your Own Flows

If the reference implementation does not meet your needs, then you can build your own flows using this project as a library of convenience functions.

Look at `clientAutoMode` in [`src/index.ts`](./src/index.ts) to see how you can use the convenience functions to build a ACME client implementation.

## Project Structure

|                       Path              | Description |
| ----                                    | ------------|
| [src](src)                              | Contains your source code that will be compiled to the `dist/` directory. |
| [integration-tests](integration-tests)  | Contains your source code of tests. |

## Contributing

Please see the [contributing guide](https://github.com/nginxinc/njs-acme-experemental/blob/main/CONTRIBUTING.md) for guidelines on how to best contribute to this project.

## License

[Apache License, Version 2.0](https://github.com/nginxinc/njs-acme-experemental/blob/main/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2023
