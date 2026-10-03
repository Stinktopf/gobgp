# syntax=docker/dockerfile:1
# Router image of the emulation lab. gobgpd and its API definitions come from
# the "daemon" build context, which the lab fills from any git ref; the
# controller always comes from this tree. Build manually with:
#   docker build --build-context daemon=. -t obgp-lab/router .

FROM golang:1.24 AS build
WORKDIR /src
COPY --from=daemon go.mod go.sum ./
RUN go mod download
COPY --from=daemon . .
RUN CGO_ENABLED=0 go build -o /out/gobgpd ./cmd/gobgpd \
 && CGO_ENABLED=0 go build -o /out/gobgp ./cmd/gobgp

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
# iptables and tc inject link failures and degradation.
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --no-install-project --only-group controller
COPY --from=daemon proto/ proto/
RUN uv run --no-sync python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/api/*.proto
COPY --from=build /out/ /usr/local/bin/
COPY controller/app.py .
EXPOSE 179 8080
ENTRYPOINT ["uv", "run", "--no-sync", "app.py"]
