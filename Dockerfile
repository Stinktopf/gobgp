FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o gobgpd ./cmd/gobgpd
RUN go build -o gobgp  ./cmd/gobgp

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl iproute2 tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-cache --no-editable
COPY --from=build /app/gobgpd /usr/local/bin/
COPY --from=build /app/gobgp  /usr/local/bin/

COPY entrypoint.py .
COPY proto/ ./proto/
COPY README.md ./

RUN mkdir -p apipb

RUN uv run --with grpcio-tools -m grpc_tools.protoc \
    -I ./proto \
    --python_out=./apipb \
    --grpc_python_out=./apipb \
    ./proto/api/*.proto && \
    touch apipb/__init__.py && \
    touch apipb/api/__init__.py && \
    mkdir -p /app/api && \
    cp -r apipb/api/* /app/api/ && \
    touch /app/api/__init__.py

EXPOSE 179 8080
ENTRYPOINT ["uv", "run", "entrypoint.py"]
