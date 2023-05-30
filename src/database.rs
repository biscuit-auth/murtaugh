use crate::types::*;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use sqlx::{postgres::PgNotification, Pool, Postgres};

pub struct RevocationIdRow {
    pub revocation_id: RevocationId,
    pub issuer_id: IssuerId,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: DateTime<Utc>,
}

pub async fn revoke_id(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
    revocation_id: &RevocationId,
    expires_at: &Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    let notification: String = serde_json::to_string(&(revocation_id, expires_at)).unwrap();
    sqlx::query!(
        "insert into revoked_block (issuer_id, revocation_id, expires_at) values($1, $2, $3)",
        issuer_id.0,
        revocation_id.0,
        expires_at.map(|dt| dt.naive_utc()),
    )
    .execute(pool)
    .await?;
    sqlx::query!(
        "select pg_notify($1, $2)",
        issuer_id.0.to_string(),
        notification,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_revoked_ids(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
) -> Result<Vec<RevocationIdRow>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id, issuer_id, expires_at, revoked_at from revoked_block where issuer_id = $1 and (expires_at is null or expires_at > now())",
        issuer_id.0
    )
    .fetch_all(pool)
    .await?;
    Ok(res
        .iter()
        .map(|x| RevocationIdRow {
            revocation_id: RevocationId(x.revocation_id.clone()),
            issuer_id: IssuerId(x.issuer_id.clone()),
            expires_at: x.expires_at.map(|ndt| DateTime::from_utc(ndt, Utc)),
            revoked_at: DateTime::from_utc(x.revoked_at, Utc),
        })
        .collect())
}

pub async fn check_if_revoked(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
    ids: &[RevocationId],
) -> Result<Vec<RevocationIdRow>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id, issuer_id, expires_at, revoked_at from revoked_block where issuer_id = $1 and revocation_id = any($2) and (expires_at is null or expires_at > now())",
        issuer_id.0,
        &ids.iter().map(|rid| rid.0.clone()).collect::<Vec<_>>(),
    )
    .fetch_all(pool)
    .await?;
    Ok(res
        .iter()
        .map(|x| RevocationIdRow {
            revocation_id: RevocationId(x.revocation_id.clone()),
            issuer_id: IssuerId(x.issuer_id),
            expires_at: x.expires_at.map(|ndt| DateTime::from_utc(ndt, Utc)),
            revoked_at: DateTime::from_utc(x.revoked_at, Utc),
        })
        .collect())
}

pub async fn listen_issuer_events(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
) -> Result<impl Stream<Item = Result<PgNotification, sqlx::Error>>, sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen(&issuer_id.0.to_string()).await?;
    Ok(listener.into_stream())
}
