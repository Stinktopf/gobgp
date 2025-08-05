FROM golang:1.24 AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o gobgpd ./cmd/gobgpd
RUN go build -o gobgp ./cmd/gobgp

FROM debian:bookworm-slim
COPY --from=build /app/gobgpd /usr/local/bin/
COPY --from=build /app/gobgp /usr/local/bin/