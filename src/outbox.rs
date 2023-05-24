use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, State},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, TypedHeader,
};

use chrono::{TimeZone, Utc};
use rusqlite::ErrorCode;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    actor::{actor_id, private_key, validate},
    follow::{accept_following, add_following, reject_following, remove_following},
    object::create_object,
    protocol::{
        activity_type, clean, object_object, object_type, recipients, Created, JsonLD, ACTIVITIES,
        ACTIVITY_STREAMS_NS,
    },
    util::{copy, send_to_recipient, trigger_send_to_recipient},
    AppState,
};

#[derive(Error, Debug)]
pub enum OutboxError {
    #[error("internal outbox error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("outbox operation required authentication: {0}")]
    NoAuth(anyhow::Error),
    #[error("outbox operation not authorized: {0}")]
    AuthFailed(anyhow::Error),
    #[error("outbox activity {0} already exists")]
    Duplicate(String),
    #[error("outbox activity id {0} is invalid")]
    Invalid(String),
}

impl IntoResponse for OutboxError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            OutboxError::Duplicate(id) => (
                StatusCode::BAD_REQUEST,
                format!("activity `{id}` already exists"),
            ),
            OutboxError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            OutboxError::Invalid(err) => (StatusCode::BAD_REQUEST, err),
            OutboxError::NoAuth(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
            OutboxError::AuthFailed(err) => (StatusCode::FORBIDDEN, err.to_string()),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl From<SystemTimeError> for OutboxError {
    fn from(value: SystemTimeError) -> Self {
        OutboxError::Internal(anyhow!(value))
    }
}
/*
impl From<ResourceError> for OutboxError {
    fn from(value: ResourceError) -> Self {
        OutboxError::Internal(value.into())
    }
}
 */

pub(crate) async fn post_outbox(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    JsonLD(mut new_activity): JsonLD<Value>,
) -> Result<Created, OutboxError> {
    let token_username = validate(&state, auth.token())
        .map_err(OutboxError::NoAuth)?
        .username;
    if token_username != username {
        return Err(OutboxError::AuthFailed(anyhow!(
            "can only post to own outbox"
        )));
    }
    let short_id = Uuid::new_v4();
    let mut activity_type = activity_type(&new_activity)?.to_string();
    if !ACTIVITIES.contains(&activity_type.as_str()) {
        activity_type = "Create".to_string();
        let mut wrap_activity = json!({
            "@context": ACTIVITY_STREAMS_NS,
            "object": new_activity,
            "type": activity_type,
        });
        copy(
            &new_activity,
            &mut wrap_activity,
            &["to", "bto", "cc", "bcc"],
        );
        new_activity = wrap_activity;
    }
    let activity_id = format!("https://{}/actors/{username}/outbox/{short_id}", state.base);
    add(&mut new_activity, "id", activity_id.clone())?;
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let activity_state =
        preprocess_activity(&state, &username, &mut new_activity, &activity_type, iat)?;

    {
        let conn = &state.conn()?;
        match conn.execute(
            "INSERT INTO Outbox VALUES (?1, ?2, ?3, ?4, ?5)",
            (&username, &short_id, &activity_type, iat, &new_activity),
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, msg))
                if err.code == ErrorCode::ConstraintViolation
                    && matches!(&msg,Some(msg) if msg.contains("UNIQUE") && msg.contains("Outbox")) =>
            {
                return Err(OutboxError::Duplicate(short_id.to_string()))
            }
            Err(err) => {
                return Err(OutboxError::Internal(anyhow!(err)));
            }
        }
    }
    let ret = Created::new(activity_state.location().map(|s| s.to_owned()));
    postprocess_activity(
        state,
        &username,
        activity_id,
        new_activity,
        activity_state,
        iat,
    )
    .await?;

    Ok(ret)
}

fn preprocess_activity(
    state: &AppState,
    username: &str,
    activity: &mut Value,
    activity_type: &str,
    iat: i64,
) -> Result<ActivityState, OutboxError> {
    let ts = Utc.timestamp_opt(iat, 0).unwrap().to_rfc3339();
    let actor = format!("https://{}/actors/{username}", state.base);
    add(activity, "published", ts.clone())?;
    add(activity, "actor", actor.clone())?;
    if activity_type == "Create" {
        let object_type = object_type(activity)?.to_string();

        let object_short_id = Uuid::new_v4();
        let object_id = format!(
            "https://{}/actors/{username}/objects/{}/{object_short_id}",
            state.base,
            object_type.to_lowercase()
        );
        match activity.pointer_mut("/object") {
            Some(obj) => {
                add(obj, "published", ts)?;
                add(obj, "id", object_id.clone())?;
                add(obj, "attributedTo", actor)?;
            }
            None => {
                return Err(OutboxError::Invalid(String::from(
                    "no `/object` JSON object found in Create activity",
                )))
            }
        };
        let recipients = recipients(activity)
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        clean(activity);
        Ok(ActivityState::Create {
            object_type,
            object_short_id,
            object_id,
            recipients,
        })
    } else if activity_type == "Follow" {
        let following = match activity.pointer("/object").and_then(|v| v.as_str()) {
            Some(activity) => activity.to_string(),
            None => {
                return Err(OutboxError::Invalid(String::from(
                    "no `/object` string found in Follow activity",
                )));
            }
        };
        Ok(ActivityState::FollowRequest { following })
    } else if activity_type == "Accept" {
        if object_type(activity)? != "Follow" {
            return Err(OutboxError::Invalid(String::from(
                "no Follow found in Accept",
            )));
        }

        let following = object_object(activity)?.to_string();
        Ok(ActivityState::FollowAccept { following })
    } else if activity_type == "Reject" {
        if object_type(activity)? != "Follow" {
            return Err(OutboxError::Invalid(String::from(
                "no Follow found in Reject",
            )));
        }
        let following = object_object(activity)?.to_string();
        Ok(ActivityState::FollowReject { following })
    } else if activity_type == "Undo" {
        if object_type(activity)? != "Follow" {
            return Err(OutboxError::Invalid(String::from(
                "no Follow found in Undo",
            )));
        }
        let following = object_object(activity)?.to_string();
        Ok(ActivityState::FollowUndo { following })
    } else {
        Ok(ActivityState::Other)
    }
}

async fn postprocess_activity(
    state: Arc<AppState>,
    username: &str,
    activity_id: String,
    activity: Value,
    activity_state: ActivityState,
    iat: i64,
) -> Result<()> {
    let activity_id = Arc::new(activity_id);
    let activity = Arc::new(activity);
    match activity_state {
        ActivityState::Create {
            object_short_id,
            object_type,
            recipients,
            ..
        } if activity.pointer("/object").is_some() => {
            create_object(
                &state,
                username,
                &object_short_id,
                &object_type,
                activity.pointer("/object").unwrap(),
                iat,
            )?;
            let actor_id = Arc::new(actor_id(&state, username));
            let key = Arc::new(private_key(&state, username)?);
            for recipient in recipients.into_iter() {
                tokio::spawn({
                    let st = state.clone();
                    let actor_id = actor_id.clone();
                    let key = key.clone();
                    let aid = Arc::clone(&activity_id);
                    let aid2 = Arc::clone(&activity_id);
                    let activity = activity.clone();
                    async move {
                        match send_to_recipient(
                            st,
                            recipient.clone(),
                            actor_id,
                            key,
                            aid,
                            activity,
                            iat,
                        )
                        .await
                        {
                            Ok(_) => {
                                tracing::info!("Sent activity {aid2} to {recipient}")
                            }
                            Err(err) => tracing::error!(
                                "Sending activity {aid2} to {recipient} failed: {err}"
                            ),
                        };
                    }
                });
            }
        }
        ActivityState::Create { .. } => return Err(anyhow!("Create activity with no object")),
        ActivityState::FollowRequest { following } => {
            add_following(&state, username, &following, iat)?;
            trigger_send_to_recipient(state, username, following, activity_id, activity, iat)
                .await?;
        }
        ActivityState::FollowAccept { following } => {
            accept_following(&state, username, &following)?;
        }
        ActivityState::FollowReject { following } => {
            reject_following(&state, username, &following)?;
        }
        ActivityState::FollowUndo { following } => {
            remove_following(&state, username, &following)?;
            trigger_send_to_recipient(state, username, following, activity_id, activity, iat)
                .await?;
        }
        ActivityState::Other => {}
    }
    Ok(())
}

pub enum ActivityState {
    Other,
    Create {
        object_type: String,
        object_short_id: Uuid,
        object_id: String,
        recipients: HashSet<String>,
    },
    FollowRequest {
        following: String,
    },
    FollowAccept {
        following: String,
    },
    FollowReject {
        following: String,
    },
    FollowUndo {
        following: String,
    },
}

impl ActivityState {
    fn location(&self) -> Option<&str> {
        match self {
            ActivityState::Create { object_id, .. } => Some(object_id),
            ActivityState::Other => None,
            ActivityState::FollowRequest { .. } => None,
            ActivityState::FollowAccept { .. } => None,
            ActivityState::FollowReject { .. } => None,
            ActivityState::FollowUndo { .. } => None,
        }
    }
}

fn add<T>(to: &mut Value, key: &str, value: T) -> Result<(), OutboxError>
where
    T: Into<Value>,
{
    match to.as_object_mut() {
        Some(map) => map.insert(key.to_string(), value.into()),
        None => {
            return Err(OutboxError::Invalid(String::from(
                "activity not a JSON object",
            )))
        }
    };
    Ok(())
}
