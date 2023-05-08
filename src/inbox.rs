use crate::{
    protocol::JsonLD,
    util::{OrderedCollection, Pagination},
    AppState,
};
use anyhow::{anyhow, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub(crate) enum InboxError {
    #[error("internal inbox error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for InboxError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            InboxError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            //     InboxError::AuthFailed(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl From<rusqlite::Error> for InboxError {
    fn from(value: rusqlite::Error) -> Self {
        InboxError::Internal(anyhow!(value))
    }
}

pub(crate) async fn get_shared_inbox(
    State(state): State<Arc<AppState>>,
    Query(pagination): Query<Pagination>,
) -> Result<JsonLD<OrderedCollection>, InboxError> {
    let conn = &state.conn()?;
    let mut stmt = conn.prepare(
        "SELECT data FROM SharedInbox ORDER BY created DESC, id ASC LIMIT 25 OFFSET (?1 * 25) ",
    )?;

    let ordered_items: Result<Vec<Value>> = stmt
        .query_map([&pagination.page.unwrap_or(0)], |row| {
            let data: Value = row.get(0)?;
            Ok(data)
        })?
        .map(value_from_row)
        .collect();
    let ordered_items = ordered_items?;
    eprintln!("get shared {ordered_items:?}");
    let len = ordered_items.len();

    let c = OrderedCollection {
        ordered_items,
        total_items: len as u64,
    };
    Ok(JsonLD(c))
}

pub fn value_from_row<E>(row: rusqlite::Result<Value, E>) -> Result<Value>
where
    E: Into<anyhow::Error>,
{
    match row {
        Ok(value) => Ok(value),
        Err(err) => Err(anyhow!(err)),
    }
}

pub(crate) fn add_shared_inbox(
    state: &AppState,
    id: &Uuid,
    activity_type: &str,
    data: &Value,
    iat: u64,
) -> Result<(), InboxError> {
    let conn = &state.conn()?;
    conn.execute(
        "INSERT OR IGNORE INTO SharedInbox (id, activity_type, created, data) VALUES (?1, ?2, ?3, ?4)",
        (
            id,
            &activity_type.to_lowercase(),
            iat,
            data,
        ),
    )?;
    Ok(())
}
