FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o gobgpd ./cmd/gobgpd
RUN go build -o gobgp  ./cmd/gobgp

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip curl iproute2 && \
    pip install --break-system-packages fastapi uvicorn && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /app/gobgpd /usr/local/bin/
COPY --from=build /app/gobgp  /usr/local/bin/

COPY entrypoint.py /entrypoint.py
EXPOSE 179 8080
ENTRYPOINT ["python3", "/entrypoint.py"]
