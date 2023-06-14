FROM nginx:1.24.0

# following installation steps from http://nginx.org/en/linux_packages.html#Debian
RUN --mount=type=cache,target=/var/cache/apt <<EOF
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update
    apt-get -qq install --yes --no-install-recommends --no-install-suggests \
        curl gnupg2 ca-certificates debian-archive-keyring inotify-tools
    update-ca-certificates
    apt-get remove --purge --auto-remove --yes
    rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list
EOF
RUN mkdir -p /usr/lib/nginx/njs_modules
