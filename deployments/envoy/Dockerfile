FROM golang:alpine AS builder

ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY pkg/ ./pkg/
COPY internal/gen/ ./internal/gen/
COPY cmd/trifecta-extproc/ ./cmd/trifecta-extproc/
COPY cmd/mock-llm-sse/ ./cmd/mock-llm-sse/

RUN go build -trimpath -ldflags="-s -w" -o /out/trifecta-extproc ./cmd/trifecta-extproc && \
    go build -trimpath -ldflags="-s -w" -o /out/mock-llm-sse ./cmd/mock-llm-sse

FROM alpine:3.21 AS trifecta-extproc
COPY --from=builder /out/trifecta-extproc /usr/local/bin/trifecta-extproc
EXPOSE 9002
ENTRYPOINT ["/usr/local/bin/trifecta-extproc"]
CMD ["--listen", ":9002"]

FROM alpine:3.21 AS mock-llm-sse
COPY --from=builder /out/mock-llm-sse /usr/local/bin/mock-llm-sse
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mock-llm-sse"]
CMD ["--listen", ":8080"]
