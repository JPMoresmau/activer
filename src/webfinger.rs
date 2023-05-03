use std::sync::Arc;

use anyhow::anyhow;
use axum::{
    extract::{Query, State},
    Json,
};
use axum_core::response::{IntoResponse, Response};
use http::StatusCode;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{protocol::LD_CONTENT_TYPE, AppState};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WebFingerQuery {
    resource: String,
}

pub enum WebFingerError {
    Internal(anyhow::Error),
    UnknownAccount(String),
    UnsupportedResource(String),
    UnsupportedQuery(String),
}

impl IntoResponse for WebFingerError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            WebFingerError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            WebFingerError::UnknownAccount(name) => {
                (StatusCode::NOT_FOUND, format!("account `{name}` not found"))
            }
            WebFingerError::UnsupportedQuery(query) => (
                StatusCode::BAD_REQUEST,
                format!("query `{query}` not understood"),
            ),
            WebFingerError::UnsupportedResource(query) => (
                StatusCode::BAD_REQUEST,
                format!("resource `{query}` not supported"),
            ),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl<T> From<T> for WebFingerError
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        WebFingerError::Internal(anyhow!(value))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WebFingerResult {
    subject: String,
    links: Vec<Link>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Link {
    rel: String,
    #[serde(rename = "type")]
    r#type: String,
    href: String,
}

pub(crate) async fn resource(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebFingerQuery>,
) -> Result<Json<WebFingerResult>, WebFingerError> {
    match query.resource.split_once(':') {
        Some(("acct", account)) => match account.split_once('@') {
            Some((username, base)) if base == state.base => {
                let conn = Connection::open(&state.db_path)?;
                let _: i32 = match conn.query_row(
                    "SELECT 1 FROM Actors where username=?1",
                    [&username],
                    |row| row.get(0),
                ) {
                    Ok(data) => data,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        return Err(WebFingerError::UnknownAccount(account.to_string()))
                    }
                    Err(err) => return Err(WebFingerError::Internal(anyhow!(err))),
                };
                let result = WebFingerResult {
                    subject: query.resource.to_owned(),
                    links: vec![Link {
                        rel: "self".to_string(),
                        r#type: LD_CONTENT_TYPE.to_string(),
                        href: format!("https://{}/actors/{}", state.base, username),
                    }],
                };
                Ok(Json(result))
            }
            _ => Err(WebFingerError::UnknownAccount(account.to_string())),
        },
        Some((resource, _)) => Err(WebFingerError::UnsupportedResource(resource.to_string())),
        None => Err(WebFingerError::UnsupportedQuery(query.resource)),
    }
}
