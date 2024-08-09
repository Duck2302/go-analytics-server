FROM golang:latest

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .


RUN CGO_ENABLED=1 go build main.go

EXPOSE 5000

CMD ["./main"]

