
ARG NGINX_VERSION=1.24.0
ARG NJS_VERSION=0.7.12

FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
ARG NJS_VERSION
ENV NJS_ACME_DIR=/var/nginx/acme/data

# following installation steps from http://nginx.org/en/linux_packages.html#Debian
RUN --mount=type=cache,target=/var/cache/apt <<EOF
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update
    apt-get -qq install --yes --no-install-recommends --no-install-suggests \
        curl gnupg2 ca-certificates debian-archive-keyring
    update-ca-certificates
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
        | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    gpg --dry-run --quiet --no-keyring --import --import-options import-show \
        /usr/share/keyrings/nginx-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
        http://nginx.org/packages/mainline/ubuntu $(echo $PKG_RELEASE | cut -f2 -d~) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    apt-get -qq install --yes --no-install-recommends --no-install-suggests \
        curl nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}
    apt-get remove --purge --auto-remove --yes
    rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list
EOF
RUN mkdir -p $NJS_ACME_DIR
