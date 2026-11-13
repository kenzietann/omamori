FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release
FROM debian:trixie-slim
COPY --from=build /src/target/release/lab-actix /app
CMD ["/app"]
