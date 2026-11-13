FROM golang:1.26 AS build
WORKDIR /src
COPY main.go .
RUN go mod init lab && go get github.com/gin-gonic/gin@v1.10.0 github.com/labstack/echo/v4@v4.13.3 github.com/go-chi/chi/v5@v5.2.0 && go mod tidy && CGO_ENABLED=0 go build -o /app .
FROM debian:trixie-slim
COPY --from=build /app /app
ENTRYPOINT ["/app"]
