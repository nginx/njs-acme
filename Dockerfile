
ARG NGINX_VERSION=1.23.3
ARG NJS_VERSION=0.7.10

FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
ARG NJS_VERSION

RUN --mount=type=cache,target=/var/cache/apt <<EOF
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    echo "deb https://nginx.org/packages/mainline/debian/ $(echo $PKG_RELEASE | cut -f2 -d~) nginx" >> /etc/apt/sources.list.d/nginx.list
    apt-get -qq update
    apt-get -qq install --yes --no-install-recommends --no-install-suggests \
        curl nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}
    apt-get remove --purge --auto-remove --yes
    rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list
EOF
