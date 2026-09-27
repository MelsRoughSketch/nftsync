FROM golang:1.26

RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
