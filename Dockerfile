# syntax=docker/dockerfile:1
ARG NGINX_VERSION=1.25.3

FROM node:20 AS builder
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
