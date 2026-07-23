ARG ALPINE_VERSION=3.24.1
ARG COSMOCC_VERSION=4.0.2
ARG COSMOCC_B3SUM=51a43465eeb9303a107b8cf165af9df6a62c96aea88b000ee66a9b90fd5afa04
ARG COSMOCC_URL="https://github.com/jart/cosmopolitan/releases/download/${COSMOCC_VERSION}/cosmocc-${COSMOCC_VERSION}.zip"

FROM alpine:${ALPINE_VERSION} AS builder
ARG COSMOCC_VERSION
ARG COSMOCC_B3SUM
ARG COSMOCC_URL
WORKDIR /cosmocc
RUN apk add --no-cache b3sum=1.8.5-r0
RUN echo "${COSMOCC_B3SUM}  cosmocc-${COSMOCC_VERSION}.zip" > cosmocc.zip.b3sum \
    && wget -q "${COSMOCC_URL}" -O "cosmocc-${COSMOCC_VERSION}.zip" \
    && b3sum -c cosmocc.zip.b3sum \
    && unzip -q "cosmocc-${COSMOCC_VERSION}.zip" \
    && rm "cosmocc-${COSMOCC_VERSION}.zip" cosmocc.zip.b3sum

WORKDIR /app
ARG FINPASS_VERSION=devel
COPY Makefile ./
COPY c/ ./c/
COPY internal/words.txt ./internal/
RUN PATH=$PATH:/cosmocc/bin make ape APE_VERSION="${FINPASS_VERSION}"
