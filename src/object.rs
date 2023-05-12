use crate::{
    actor::validate,
    protocol::{recipients, JsonLD, PUBLIC},
    AppState,
};
use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, State},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, TypedHeader,
};
use rusqlite::ErrorCode;
use serde_json::{json, Value};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub(crate) enum ObjectError {
    #[error("internal object error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("object operation not authorized: {0}")]
    AuthFailed(anyhow::Error),
    #[error("object {0} already exists")]
    Duplicate(String),
    #[error("object id {0}/{1}/{2} not found")]
    Unknown(String, String, Uuid),
}

impl IntoResponse for ObjectError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ObjectError::Duplicate(id) => (
                StatusCode::BAD_REQUEST,
                format!("activity `{id}` already exists"),
            ),
            ObjectError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ObjectError::Unknown(..) => (StatusCode::NOT_FOUND, self.to_string()),
            ObjectError::AuthFailed(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
/*
impl<T> From<T> for ResourceError
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        ResourceError::Internal(anyhow!(value))
    }
}*/

pub(crate) async fn get_object(
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    State(state): State<Arc<AppState>>,
    Path((username, object_type, object_id)): Path<(String, String, Uuid)>,
) -> Result<JsonLD<Value>, ObjectError> {
    let conn = &state.conn()?;
    let data = match conn.query_row(
        "SELECT data FROM Objects where username=?1 AND object_type=?2 AND id=?3",
        (&username, &object_type, &object_id),
        |row| row.get(0),
    ) {
        Ok(data) => data,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(ObjectError::Unknown(username, object_type, object_id))
        }

        Err(err) => return Err(ObjectError::Internal(anyhow!(err))),
    };
    let recipients = recipients(&data);
    if !recipients.iter().any(|r| *r == PUBLIC) {
        match auth {
            Some(auth) => {
                let web_id = validate(&state, auth.token())
                    .map_err(ObjectError::AuthFailed)?
                    .web_id;
                // No access, let's pretend the resource doesn't exist.
                if !recipients.iter().any(|r| *r == web_id) {
                    return Err(ObjectError::Unknown(username, object_type, object_id));
                }
            }
            None => {
                return Err(ObjectError::AuthFailed(anyhow!(
                    "no authorization provided"
                )))
            }
        }
    }
    Ok(JsonLD(data))
}

pub(crate) fn create_object(
    state: &AppState,
    username: &str,
    object_id: &Uuid,
    object_type: &str,
    object: &Value,
    iat: i64,
) -> Result<(), ObjectError> {
    let conn = &state.conn()?;
    match conn.execute(
        "INSERT INTO Objects (username, id, object_type, created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            username,
            object_id,
            &object_type.to_lowercase(),
            iat,
            object,
        ),
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, msg))
            if err.code == ErrorCode::ConstraintViolation
                && matches!(&msg,Some(msg) if msg.contains("UNIQUE") && msg.contains("Objects")) =>
        {
            return Err(ObjectError::Duplicate(object_id.to_string()))
        }
        Err(err) => {
            return Err(ObjectError::Internal(anyhow!(err)));
        }
    }
    Ok(())
}
