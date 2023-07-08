# syntax=docker/dockerfile:1
ARG NGINX_VERSION=1.24.0

FROM node:18 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/app/.npm \
    npm set cache /app/.npm && \
    npm ci
COPY . .
RUN npm run build

FROM nginx:${NGINX_VERSION}
COPY --from=builder /app/dist/acme.js /usr/lib/nginx/njs_modules/acme.js
COPY ./examples/nginx.conf /etc/nginx/nginx.conf
RUN mkdir /etc/nginx/njs-acme
RUN chown nginx: /etc/nginx/njs-acme

# install the latest njs > 0.8.0 (not yet bundled with nginx-1.25.1)
RUN --mount=type=cache,target=/var/cache/apt <<EOF
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    apt -qq update
    apt install -qq  --yes --no-install-recommends --no-install-suggests \
        curl gnupg2 ca-certificates lsb-release debian-archive-keyring
    update-ca-certificates
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
        | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    gpg --dry-run --quiet --no-keyring --import --import-options import-show \
        /usr/share/keyrings/nginx-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
        http://nginx.org/packages/mainline/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    apt update -qq
    apt install -qq  --yes --no-install-recommends --no-install-suggests \
        nginx-module-njs
    apt remove --purge --auto-remove --yes
    rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list
EOF
