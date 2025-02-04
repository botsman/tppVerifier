FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

COPY . .

RUN cd app && go build -o /app/main .

FROM scratch

COPY --from=builder /app/main /app/main

ENTRYPOINT ["/app/main"]
