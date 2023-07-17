FROM node:20-bullseye

ENV NJS_ACME_DIR=/etc/nginx/njs-acme/

# installing nginx and njs so we can use it while running tests
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
        nginx nginx-module-njs
    apt remove --purge --auto-remove --yes
    rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list
EOF
RUN mkdir -p ${NJS_ACME_DIR}

WORKDIR /app

COPY package*.json .
RUN npm ci
CMD npm run test
