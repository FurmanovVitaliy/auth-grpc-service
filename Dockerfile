#base go image
FROM golang:1.23.3-alpine AS builder

RUN apk --no-cache add bash git make gcc gettext musl-dev

WORKDIR /usr/local/src/

COPY [ "go.mod", "go.sum", "./" ]

RUN go mod download

#build the binary

COPY . ./

RUN go build -o ./bin/app cmd/sso/main.go

#final image
FROM alpine:latest

RUN apk update &&\
    apk upgrade -U &&\
    apk add ca-certificates &&\
    rm -rf /var/cache/*

COPY --from=builder /usr/local/src/bin/app /

CMD ["/app"]
