// A small actix-web API with its Logger middleware and env_logger, as the actix-web documentation sets it up.
use actix_web::{get, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Credentials { username: String, password: String }

#[post("/auth/login")]
async fn login(request: HttpRequest, body: web::Json<Credentials>) -> HttpResponse {
    if body.username == "alice" && body.password == "Summer2026!" {
        return HttpResponse::Ok().body("{\"token\":\"t\"}");
    }
    let peer = request.peer_addr().map(|address| address.ip().to_string()).unwrap_or_default();
    log::warn!("Failed login for {} from {}", body.username, peer);
    HttpResponse::Unauthorized().body("{\"error\":\"invalid credentials\"}")
}

#[get("/api/items")]
async fn items(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    if id.contains('\'') {
        log::error!("diesel: syntax error at or near \"{}\"", id);
        return HttpResponse::InternalServerError().body("{\"error\":\"server error\"}");
    }
    HttpResponse::Ok().body("[]")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(|| App::new().wrap(Logger::default()).service(login).service(items))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
