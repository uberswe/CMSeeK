FROM golang:1.17.5-alpine AS builder

RUN apk update && apk upgrade && apk add --no-cache bash git && apk add --no-cache chromium

WORKDIR /app

COPY . .
RUN apk --no-cache add ca-certificates

WORKDIR /app/api

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "main" -ldflags="-w -s" ./main.go

FROM python:3-alpine

WORKDIR app

RUN apk add --no-cache git py3-pip

COPY --from=builder /app/api/main /main
COPY --from=builder /app /app

RUN pip install -r requirements.txt

CMD ["/main"]

EXPOSE 8080