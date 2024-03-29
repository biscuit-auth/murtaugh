use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
pub struct IssuerId(pub Uuid);

#[derive(Clone, Deserialize, Serialize)]
pub struct RevocationId(pub String);
