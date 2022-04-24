FROM golang:1.18.0-alpine AS builder
WORKDIR /go
COPY go.mod src/
COPY *.go src/
COPY client/client.go src/client/
RUN cd src/client && go build

FROM alpine:latest
LABEL golang.version="1.18.0"
WORKDIR /opt/qproxy/
COPY --from=builder /go/src/client/client ./
EXPOSE 2080

ENTRYPOINT ["/opt/qproxy/client"]
