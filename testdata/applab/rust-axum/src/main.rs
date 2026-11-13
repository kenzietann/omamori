// A small Axum API with the TraceLayer of tower-http and the default text output of tracing-subscriber,
// as most Axum examples set it up.
use axum::{extract::{ConnectInfo, Query}, http::StatusCode, routing::{get, post}, Json, Router};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};
use tower_http::trace::TraceLayer;

#[derive(Deserialize)]
struct Credentials { username: String, password: String }

async fn login(ConnectInfo(peer): ConnectInfo<SocketAddr>, Json(body): Json<Credentials>) -> (StatusCode, &'static str) {
    if body.username == "alice" && body.password == "Summer2026!" {
        return (StatusCode::OK, "{\"token\":\"t\"}");
    }
    tracing::warn!("Failed login for {} from {}", body.username, peer.ip());
    (StatusCode::UNAUTHORIZED, "{\"error\":\"invalid credentials\"}")
}

async fn items(Query(query): Query<HashMap<String, String>>) -> (StatusCode, &'static str) {
    let id = query.get("id").cloned().unwrap_or_default();
    if id.contains('\'') {
        tracing::error!("sqlx: syntax error at or near \"{}\"", id);
        return (StatusCode::INTERNAL_SERVER_ERROR, "{\"error\":\"server error\"}");
    }
    (StatusCode::OK, "[]")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info,tower_http=debug").init();
    let app = Router::new().route("/auth/login", post(login)).route("/api/items", get(items)).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
