FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM golang:1.24-alpine AS server-build

WORKDIR /server
COPY go.mod ./
COPY server ./server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /crypto-toolbox-server ./server

FROM alpine:3.21

COPY --from=server-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build /app/dist /srv
COPY --from=server-build /crypto-toolbox-server /usr/local/bin/crypto-toolbox-server

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/crypto-toolbox-server"]
