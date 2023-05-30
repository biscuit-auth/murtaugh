use crate::types::*;
use futures_util::Stream;
use sqlx::{postgres::PgNotification, Pool, Postgres};

pub async fn revoke_id(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
    revocation_id: &RevocationId,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "insert into revoked_block (issuer_id, revocation_id) values($1, $2)",
        issuer_id.0,
        revocation_id.0
    )
    .execute(pool)
    .await?;
    sqlx::query!(
        "select pg_notify($1, $2)",
        issuer_id.0.to_string(),
        revocation_id.0,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_revoked_ids(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
) -> Result<Vec<RevocationId>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id from revoked_block where issuer_id = $1",
        issuer_id.0
    )
    .fetch_all(pool)
    .await?;
    Ok(res
        .iter()
        .map(|x| RevocationId(x.revocation_id.clone()))
        .collect())
}

pub async fn check_if_revoked(
    pool: &Pool<Postgres>,
    issuer_id: &IssuerId,
    ids: &[RevocationId],
) -> Result<Vec<RevocationId>, sqlx::Error> {
    let res = sqlx::query!(
        "select revocation_id from revoked_block where issuer_id = $1 and revocation_id = any($2)",
        issuer_id.0,
        &ids.iter().map(|rid| rid.0.clone()).collect::<Vec<_>>(),
    )
    .fetch_all(pool)
    .await?;
    Ok(res
        .iter()
        .map(|x| RevocationId(x.revocation_id.clone()))
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
