FROM node:18 AS builder
WORKDIR /app
COPY . .
RUN npm ci
RUN npm run build

FROM nginx:1.24.0
COPY --from=builder /app/dist/acme.js /usr/lib/nginx/njs_modules/acme.js
COPY ./examples/nginx.conf /etc/nginx/nginx.conf
