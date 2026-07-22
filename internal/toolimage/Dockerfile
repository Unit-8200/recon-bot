FROM golang:1.24-bookworm AS puredns-builder

ARG PUREDNS_VERSION=v2.1.1

RUN git clone --depth 1 --branch "${PUREDNS_VERSION}" \
        https://github.com/d3mondev/puredns.git /src/puredns
WORKDIR /src/puredns
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/puredns .

FROM golang:1.24-bookworm AS caduceus-builder

ARG CADUCEUS_VERSION=v1.0.5

RUN apt-get update \
    && apt-get install --no-install-recommends -y gcc \
    && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=1 GOBIN=/out go install \
    github.com/g0ldencybersec/Caduceus/cmd/caduceus@${CADUCEUS_VERSION}

FROM debian:bookworm AS massdns-builder

ARG MASSDNS_VERSION=v1.1.0

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gcc git libc6-dev make \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${MASSDNS_VERSION}" \
        https://github.com/blechschmidt/massdns.git /src/massdns
WORKDIR /src/massdns
RUN make

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 puredns

COPY --from=puredns-builder /out/puredns /usr/local/bin/puredns
COPY --from=massdns-builder /src/massdns/bin/massdns /usr/local/bin/massdns
COPY --from=caduceus-builder /out/caduceus /usr/local/bin/caduceus
COPY --chown=puredns:puredns data/puredns/n0kovo_subdomains_huge.txt /data/n0kovo_subdomains_huge.txt
COPY --chown=puredns:puredns data/puredns/resolvers.txt /data/resolvers.txt

USER puredns
WORKDIR /work
ENTRYPOINT ["puredns"]
