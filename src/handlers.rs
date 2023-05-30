use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{sse::Event, Sse},
    Json,
};
use chrono::{DateTime, Utc};
use futures_util::stream::{iter, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgNotification, Pool, Postgres};

use crate::database::*;
use crate::types::*;

#[derive(Deserialize, Serialize)]
pub struct RevokedId {
    pub revocation_id: RevocationId,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct CommaSeparatedRevocationIds {
    revocation_ids: Option<String>,
}

#[debug_handler]
pub async fn list_revoked_ids_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<IssuerId>,
    Query(revocation_ids): Query<CommaSeparatedRevocationIds>,
) -> Result<Json<Vec<RevokedId>>, StatusCode> {
    let revoked;
    if let Some(rs) = revocation_ids.revocation_ids {
        revoked = check_if_revoked(
            pool.as_ref(),
            &issuer_id,
            &rs.split(',')
                .map(|s| RevocationId(s.to_string()))
                .collect::<Vec<_>>(),
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
                revocation_id: i.revocation_id.clone(),
                expires_at: i.expires_at,
            })
            .collect(),
    ))
}

pub async fn revoke_id_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<IssuerId>,
    Json(revoked_id): Json<RevokedId>,
) -> Result<(), StatusCode> {
    let r = revoke_id(
        pool.as_ref(),
        &issuer_id,
        &revoked_id.revocation_id,
        &revoked_id.expires_at,
    )
    .await;
    match r {
        Ok(_) => Ok(()),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// translate a json-encoded PG notification into a SSE with a JSON body.
// parsing and re-serialization is done on purpose here, we don't want to
// have the database-internal representation leaked to API users
fn translate_notification(
    notification: Result<PgNotification, sqlx::Error>,
) -> Result<Event, String> {
    let payload = notification
        .map_err(|e| e.to_string())?
        .payload()
        .to_string();
    let parsed: (RevocationId, Option<DateTime<Utc>>) =
        serde_json::from_str(&payload).map_err(|e| e.to_string())?;

    Event::default()
        .json_data(RevokedId {
            revocation_id: parsed.0,
            expires_at: parsed.1,
        })
        .map_err(|e| e.to_string())
}

pub async fn issuer_emitter(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<IssuerId>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let pg_stream = listen_issuer_events(pool.as_ref(), &issuer_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stream = pg_stream.map(|e| {
        translate_notification(e).or_else(|_| Ok(Event::default().data(r#"{"error": true}"#)))
    });
    let existing = list_revoked_ids(pool.as_ref(), &issuer_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .iter()
        .map(|r| {
            Event::default()
                .json_data(RevokedId {
                    revocation_id: r.revocation_id.clone(),
                    expires_at: r.expires_at,
                })
                .or_else(|_| Ok(Event::default().data(r#"{"error": true}"#)))
        })
        .collect::<Vec<_>>();
    Ok(Sse::new(iter(existing).chain(stream)))
}
