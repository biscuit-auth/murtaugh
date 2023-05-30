use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{sse::Event, Sse},
    Json,
};
use futures_util::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use crate::database::*;
use crate::types::*;

#[derive(Serialize)]
pub struct RevokedId {
    pub revocation_id: RevocationId,
}

#[derive(Deserialize)]
pub struct RevocationIds {
    revocation_ids: Option<String>,
}

#[debug_handler]
pub async fn list_revoked_ids_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<IssuerId>,
    Query(revocation_ids): Query<RevocationIds>,
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
                revocation_id: RevocationId(i.0.to_string()),
            })
            .collect(),
    ))
}

pub async fn revoke_id_handler(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path((issuer_id, revocation_id)): Path<(IssuerId, RevocationId)>,
) -> Result<(), StatusCode> {
    let r = revoke_id(pool.as_ref(), &issuer_id, &revocation_id).await;
    match r {
        Ok(_) => Ok(()),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn issuer_emitter(
    State(pool): State<Arc<Pool<Postgres>>>,
    Path(issuer_id): Path<IssuerId>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let pg_stream = listen_issuer_events(pool.as_ref(), &issuer_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stream = pg_stream.map(|e| match e {
        Ok(e) => Ok(Event::default().data(e.payload())),
        Err(err) => {
            println!("{}", &err);
            Ok(Event::default().data("{}"))
        }
    });
    Ok(Sse::new(stream))
}
