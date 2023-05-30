use axum::{
    routing::{get, post},
    Router,
};

use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod database;
mod handlers;
mod types;

use handlers::*;

#[tokio::main]
async fn main() {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://murtaugh@localhost/murtaugh")
        .await
        .unwrap();
    let state = Arc::new(pool);
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/:issuer_id", get(list_revoked_ids_handler))
        .route("/:issuer_id/:revocation_id", post(revoke_id_handler))
        .route("/:issuer_id/events", get(issuer_emitter))
        .with_state(state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
