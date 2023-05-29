use axum::{
    debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

async fn revoke_id(
    pool: &Pool<Postgres>,
    issuer_id: &Uuid,
    revocation_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "insert into revoked_block (issuer_id, revocation_id) values($1, $2)",
        issuer_id,
        revocation_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn list_revoked_ids(
    pool: &Pool<Postgres>,
    issuer_id: &Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id from revoked_block where issuer_id = $1",
        issuer_id
    )
    .fetch_all(pool)
    .await?;
    Ok(res.iter().map(|x| x.revocation_id.clone()).collect())
}

async fn check_if_revoked(
    pool: &Pool<Postgres>,
    issuer_id: &Uuid,
    ids: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id from revoked_block where issuer_id = $1 and revocation_id = any($2)",
        issuer_id,
        ids,
    )
    .fetch_all(pool)
    .await?;
    Ok(res.iter().map(|x| x.revocation_id.clone()).collect())
}

#[tokio::main]
async fn main() {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://murtaugh@localhost/murtaugh")
        .await
        .unwrap();
    let state = Arc::new(pool);
    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/:issuer_id", get(list_revoked_ids_handler))
        .route("/:issuer_id/:revocation_id", post(revoke_id_handler))
        .with_state(state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Serialize)]
pub struct RevokedId {
    revocation_id: String,
}

#[derive(Deserialize)]
struct RevocationIds {
    revocation_ids: Option<String>,
}

#[debug_handler]
async fn list_revoked_ids_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<Uuid>,
    Query(revocation_ids): Query<RevocationIds>,
) -> Result<Json<Vec<RevokedId>>, StatusCode> {
    let revoked;
    if let Some(rs) = revocation_ids.revocation_ids {
        revoked = check_if_revoked(
            pool.as_ref(),
            &issuer_id,
            &rs.split(",").map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else {
        revoked = list_revoked_ids(pool.as_ref(), &issuer_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(
        revoked
            .iter()
            .map(|i| RevokedId {
                revocation_id: i.to_string(),
            })
            .collect(),
    ))
}

async fn revoke_id_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path((issuer_id, revocation_id)): Path<(Uuid, String)>,
) -> Result<(), StatusCode> {
    let r = revoke_id(pool.as_ref(), &issuer_id, &revocation_id).await;
    match r {
        Ok(_) => Ok(()),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
