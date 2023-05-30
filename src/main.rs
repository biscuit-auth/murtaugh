use axum::{
    routing::{get, post},
    Router,
};

use biscuit_auth::PublicKey;
use sqlx::postgres::PgPoolOptions;
use std::{env, sync::Arc};

mod auth;
mod database;
mod handlers;
mod types;

use auth::ParseBiscuit;
use handlers::*;

#[tokio::main]
async fn main() {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://murtaugh@localhost/murtaugh")
        .await
        .unwrap();

    // private
    // 0febe739e22387ccc92e19b6bb2bc1ed765b91ad37631e5e2afa2976223318ef
    // public
    // e08af2bb43155ce7582a1ae104915a0cc9d2af144904f80d6990ebc4262b90bf
    let public_key = PublicKey::from_bytes_hex(&env::var("BISCUIT_PUBLIC_KEY").unwrap()).unwrap();
    let state = Arc::new(pool);
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/:issuer_id", get(list_revoked_ids_handler))
        .route("/:issuer_id", post(revoke_id_handler))
        .route("/:issuer_id/events", get(issuer_emitter))
        .with_state(state)
        .route_layer(ParseBiscuit::new(public_key));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
