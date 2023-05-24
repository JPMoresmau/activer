use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde_json::{json, Value};
use std::sync::Arc;
use thiserror::Error;
use tokio::task::{JoinError, JoinSet};

use crate::{
    protocol::JsonLD,
    util::{get, string_from_row, OrderedCollection, Pagination},
    AppState,
};

#[derive(Error, Debug)]
pub(crate) enum FollowError {
    #[error("internal follow error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for FollowError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            FollowError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl From<rusqlite::Error> for FollowError {
    fn from(value: rusqlite::Error) -> Self {
        FollowError::Internal(anyhow!(value))
    }
}

impl From<JoinError> for FollowError {
    fn from(value: JoinError) -> Self {
        FollowError::Internal(anyhow!(value))
    }
}

pub(crate) async fn get_followers(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    Query(pagination): Query<Pagination>,
) -> Result<JsonLD<OrderedCollection>, FollowError> {
    let ordered_ids: Result<Vec<String>> = {
        let conn = &state.conn()?;
        let mut stmt = conn.prepare(
            "SELECT follower FROM Followers WHERE username=?1 ORDER BY created DESC, follower ASC LIMIT 25 OFFSET (?2 * 25) ",
        )?;

        let rs = stmt
            .query_map((&username, &pagination.page.unwrap_or(0)), |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .map(string_from_row);
        rs.collect()
    };

    let c = collect_ids(state, ordered_ids?).await?;
    Ok(JsonLD(c))
}

pub(crate) async fn get_following(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    Query(pagination): Query<Pagination>,
) -> Result<JsonLD<OrderedCollection>, FollowError> {
    let ordered_ids: Result<Vec<String>> = {
        let conn = &state.conn()?;
        let mut stmt = conn.prepare(
            "SELECT following FROM Following WHERE username=?1 AND accepted=1 ORDER BY created DESC, following ASC LIMIT 25 OFFSET (?2 * 25) ",
        )?;

        let rs = stmt
            .query_map((&username, &pagination.page.unwrap_or(0)), |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .map(string_from_row);
        rs.collect()
    };
    let c = collect_ids(state, ordered_ids?).await?;
    Ok(JsonLD(c))
}

async fn collect_ids(state: Arc<AppState>, ordered_ids: Vec<String>) -> Result<OrderedCollection> {
    let mut set = JoinSet::new();
    let mut ordered_items = Vec::with_capacity(ordered_ids.len());
    for (ix, id) in ordered_ids.into_iter().enumerate() {
        set.spawn({
            let state = Arc::clone(&state);
            async move {
                let v = get(&state, &id, None).await;
                (ix, v)
            }
        });
    }

    while let Some(r) = set.join_next().await {
        let (ix, rv) = r?;
        ordered_items.push((ix, rv?));
    }
    ordered_items.sort_by(|(ix1, _), (ix2, _)| ix1.cmp(ix2));
    let ordered_items: Vec<Value> = ordered_items.into_iter().map(|t| t.1).collect();
    let len = ordered_items.len();

    Ok(OrderedCollection {
        ordered_items,
        total_items: len as u64,
    })
}

pub(crate) fn add_follower(
    state: &AppState,
    username: &str,
    id: &str,
    iat: i64,
) -> Result<(), FollowError> {
    let conn = &state.conn()?;
    conn.execute(
        "INSERT OR IGNORE INTO Followers (username, follower, created) VALUES (?1, ?2, ?3)",
        (username, id, iat),
    )?;
    Ok(())
}

pub(crate) fn remove_follower(
    state: &AppState,
    username: &str,
    id: &str,
) -> Result<(), FollowError> {
    let conn = &state.conn()?;
    conn.execute(
        "DELETE FROM Followers WHERE username = ?1 AND follower = ?2",
        (username, id),
    )?;
    Ok(())
}

pub(crate) fn add_following(state: &AppState, username: &str, id: &str, iat: i64) -> Result<()> {
    let conn = &state.conn()?;
    conn.execute(
        "INSERT OR IGNORE INTO Following (username, following, created) VALUES (?1, ?2, ?3)",
        (username, id, iat),
    )?;
    Ok(())
}

pub(crate) fn accept_following(state: &AppState, username: &str, id: &str) -> Result<()> {
    let conn = &state.conn()?;
    conn.execute(
        "UPDATE Following SET accepted=1 WHERE username=?1 AND following = ?2",
        (username, id),
    )?;
    Ok(())
}

pub(crate) fn reject_following(state: &AppState, username: &str, id: &str) -> Result<()> {
    let conn = &state.conn()?;
    conn.execute(
        "UPDATE Following SET accepted=-1 WHERE username=?1 AND following = ?2",
        (username, id),
    )?;
    Ok(())
}

pub(crate) fn remove_following(state: &AppState, username: &str, id: &str) -> Result<()> {
    let conn = &state.conn()?;
    conn.execute(
        "DELETE FROM Following WHERE username=?1 AND following = ?2",
        (username, id),
    )?;
    Ok(())
}
