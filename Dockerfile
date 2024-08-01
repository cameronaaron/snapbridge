
FROM golang:1.16-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o snapchat-bridge cmd/snapchat-bridge/main.go

CMD ["./snapchat-bridge"]
