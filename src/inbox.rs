use crate::{
    actor::{actor_id, validate},
    follow::{accept_following, add_follower, reject_following, remove_follower},
    protocol::{object_object, object_type, JsonLD, ACTIVITY_STREAMS_NS},
    util::{trigger_send_to_recipient, value_from_row, verify, OrderedCollection, Pagination},
    AppState,
};
use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, Query, State},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, TypedHeader,
};
use chrono::{DateTime, ParseError};
use http::HeaderMap;
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub(crate) enum InboxError {
    #[error("internal inbox error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("inbox operation required authentication: {0}")]
    NoAuth(anyhow::Error),
    #[error("inbox operation not authorized: {0}")]
    AuthFailed(anyhow::Error),
}

impl IntoResponse for InboxError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            InboxError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            InboxError::NoAuth(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
            InboxError::AuthFailed(err) => (StatusCode::FORBIDDEN, err.to_string()),
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

impl From<ParseError> for InboxError {
    fn from(value: ParseError) -> Self {
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
    let len = ordered_items.len();

    let c = OrderedCollection {
        ordered_items,
        total_items: len as u64,
    };
    Ok(JsonLD(c))
}

pub(crate) async fn get_inbox(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    Query(pagination): Query<Pagination>,
) -> Result<JsonLD<OrderedCollection>, InboxError> {
    let token_username = validate(&state, auth.token())
        .map_err(InboxError::NoAuth)?
        .username;
    if token_username != username {
        return Err(InboxError::AuthFailed(anyhow!(
            "can only retrieve own inbox"
        )));
    }
    let conn = &state.conn()?;
    let mut stmt = conn.prepare(
        "SELECT data FROM Inbox WHERE username=?1 ORDER BY created DESC, id ASC LIMIT 25 OFFSET (?2 * 25) ",
    )?;

    let ordered_items: Result<Vec<Value>> = stmt
        .query_map((&username, &pagination.page.unwrap_or(0)), |row| {
            let data: Value = row.get(0)?;
            Ok(data)
        })?
        .map(value_from_row)
        .collect();
    let ordered_items = ordered_items?;
    let len = ordered_items.len();

    let c = OrderedCollection {
        ordered_items,
        total_items: len as u64,
    };
    Ok(JsonLD(c))
}

pub(crate) async fn post_inbox(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    JsonLD(new_activity): JsonLD<Value>,
) -> Result<StatusCode, InboxError> {
    match verify(
        &state,
        "post",
        &format!("/actors/{username}/inbox"),
        &headers,
        &new_activity,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return Err(InboxError::AuthFailed(anyhow!("signature not verified"))),
        Err(err) => {
            return Err(InboxError::AuthFailed(anyhow!(
                "signature not verified: {err}"
            )))
        }
    }
    let activity_type = new_activity
        .pointer("/type")
        .ok_or_else(|| anyhow!("no activity type"))?
        .as_str()
        .ok_or_else(|| anyhow!("activity type is not a string"))?;
    let activity_id = new_activity
        .pointer("/id")
        .ok_or_else(|| anyhow!("no activity id"))?
        .as_str()
        .ok_or_else(|| anyhow!("activity id is not a string"))?;
    let published = new_activity
        .pointer("/published")
        .ok_or_else(|| anyhow!("no activity published date"))?
        .as_str()
        .ok_or_else(|| anyhow!("activity published date is not a string"))?;
    let published = DateTime::parse_from_rfc3339(published)?;
    let iat = published.timestamp();
    add_inbox(
        state,
        &username,
        activity_id,
        activity_type,
        Arc::new(new_activity.clone()),
        iat,
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) fn add_shared_inbox(
    state: &AppState,
    id: &str,
    activity_type: &str,
    data: &Value,
    iat: i64,
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

pub(crate) async fn add_inbox(
    state: Arc<AppState>,
    username: &str,
    id: &str,
    activity_type: &str,
    data: Arc<Value>,
    iat: i64,
) -> Result<(), InboxError> {
    {
        let conn = &state.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO Inbox (username, id, activity_type, created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                username,
                id,
                &activity_type.to_lowercase(),
                iat,
                &data,
            ),
        )?;
    }
    postprocess_inbox(state, username, activity_type, data).await?;
    Ok(())
}

async fn postprocess_inbox(
    state: Arc<AppState>,
    username: &str,
    activity_type: &str,
    activity: Arc<Value>,
) -> Result<()> {
    if activity_type == "Follow" {
        let from = match activity.pointer("/actor").and_then(Value::as_str) {
            Some(from) => from,
            None => return Err(anyhow!("no actor in activity")),
        };
        let v: Value = Value::clone(&activity);
        let short_id = Uuid::new_v4();
        let activity_id = format!("https://{}/actors/{username}/inbox/{short_id}", state.base);
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let response = json!({
            "context": ACTIVITY_STREAMS_NS,
            "id": activity_id,
            "actor": actor_id(&state, username),
            "type": "Accept",
            "to": from,
            "object": v,
        });
        add_follower(&state, username, from, iat)?;

        trigger_send_to_recipient(
            state,
            username,
            from.to_owned(),
            Arc::new(activity_id),
            Arc::new(response),
            iat,
        )
        .await?;
    } else if activity_type == "Accept" {
        let following = follow_object(activity_type, &activity)?;
        accept_following(&state, username, following)?;
    } else if activity_type == "Reject" {
        let following = follow_object(activity_type, &activity)?;
        reject_following(&state, username, following)?;
    } else if activity_type == "Undo" {
        let from = match activity.pointer("/actor").and_then(Value::as_str) {
            Some(from) => from,
            None => return Err(anyhow!("no actor in activity")),
        };
        remove_follower(&state, username, from)?;
    }
    Ok(())
}

fn follow_object<'a>(activity_type: &str, activity: &'a Value) -> Result<&'a str> {
    if object_type(activity)? != "Follow" {
        return Err(anyhow!("no Follow found in {activity_type}",));
    }
    object_object(activity)
}
