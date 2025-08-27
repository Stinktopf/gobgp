FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o gobgpd ./cmd/gobgpd
RUN go build -o gobgp  ./cmd/gobgp

FROM ghcr.io/astral-sh/uv:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl iproute2 && \
    rm -rf /var/lib/apt/lists/*

ENV UV_SYSTEM_PYTHON=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN uv pip install --system --no-cache -r /app/requirements.txt
COPY --from=build /app/gobgpd /usr/local/bin/
COPY --from=build /app/gobgp  /usr/local/bin/
COPY entrypoint.py /app/entrypoint.py
EXPOSE 179 8080
ENTRYPOINT ["uv", "run", "/app/entrypoint.py"]
