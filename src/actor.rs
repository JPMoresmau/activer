use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use ring::digest::{digest, SHA256};
use ring::rand::SecureRandom;
use rusqlite::{Connection, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{protocol::JsonLD, AppState};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewActor {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggedInActor {
    token: String,
    #[serde(rename = "webId")]
    web_id: String,
    #[serde(rename = "newUser")]
    new_user: bool,
}

pub enum ActorError {
    Internal(anyhow::Error),
    LoginFailed,
    Duplicate(String),
    UnknownActor(String),
}

impl IntoResponse for ActorError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ActorError::Duplicate(name) => (
                StatusCode::BAD_REQUEST,
                format!("username `{name}` already taken"),
            ),
            ActorError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ActorError::LoginFailed => (StatusCode::UNAUTHORIZED, String::from("login failed")),
            ActorError::UnknownActor(name) => (
                StatusCode::NOT_FOUND,
                format!("username `{name}` not found"),
            ),
        };
        tracing::error!(error_message);
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl<T> From<T> for ActorError
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        ActorError::Internal(anyhow!(value))
    }
}
/*
impl From<ring::error::Unspecified> for ActorError {
    fn from(_: ring::error::Unspecified) -> Self { ActorError::Internal(anyhow!("cryptographic error")) }
}*/

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Expiration time (as UTC timestamp).
    exp: u64,
    /// Issued at (as UTC timestamp).
    iat: u64,
    /// Subject.
    pub sub: String,
    #[serde(rename = "webId")]
    pub web_id: String,
}

/// Create a new actor.
pub(crate) async fn create_actor(
    State(state): State<Arc<AppState>>,
    Json(new_actor): Json<NewActor>,
) -> Result<Json<LoggedInActor>, ActorError> {
    let mut salt = [0; 8];
    let _ = &state
        .random
        .fill(&mut salt)
        .map_err(|_| ActorError::Internal(anyhow!("cryptographic error")))?;
    let salt_b64 = BASE64_STANDARD_NO_PAD.encode(salt);
    let digest = digest(
        &SHA256,
        format!("{}{salt_b64}", new_actor.password).as_bytes(),
    );
    let digest_b64 = BASE64_STANDARD_NO_PAD.encode(digest);
    let rsa = Rsa::generate(2048)?;
    let private = String::from_utf8(rsa.private_key_to_pem()?)?;
    let public = String::from_utf8(rsa.public_key_to_pem()?)?;
    let conn = Connection::open(&state.db_path)?;
    match conn.execute(
        "INSERT INTO Actors VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            &new_actor.username,
            &new_actor.email,
            public,
            private,
            &salt_b64,
            &digest_b64,
        ),
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, msg))
            if err.code == ErrorCode::ConstraintViolation
                && matches!(&msg,Some(msg) if msg.contains("UNIQUE") && msg.contains("Actors.username")) =>
        {
            return Err(ActorError::Duplicate(new_actor.username))
        }
        Err(err) => {
            return Err(ActorError::Internal(anyhow!(err)));
        }
    }
    let web_id = format!("https://{}/actors/{}", state.base, new_actor.username);
    let token = token(&state, &web_id)?;

    let created = LoggedInActor {
        token,
        web_id,
        new_user: true,
    };
    Ok(Json(created))
}

/// Create a new actor.
pub(crate) async fn login(
    State(state): State<Arc<AppState>>,
    Json(login): Json<Login>,
) -> Result<Json<LoggedInActor>, ActorError> {
    let conn = Connection::open(&state.db_path)?;
    let (salt, password): (String, String) = match conn.query_row(
        "SELECT salt,password FROM Actors where username=?1",
        [&login.username],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ) {
        Ok(data) => data,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(ActorError::LoginFailed),
        Err(err) => return Err(ActorError::Internal(anyhow!(err))),
    };
    let digest = digest(&SHA256, format!("{}{salt}", login.password).as_bytes());
    let digest_b64 = BASE64_STANDARD_NO_PAD.encode(digest);
    if digest_b64 != password {
        return Err(ActorError::LoginFailed);
    }
    let web_id = format!("https://{}/actors/{}", state.base, login.username);
    let token = token(&state, &web_id)?;

    let logged = LoggedInActor {
        token,
        web_id,
        new_user: false,
    };
    Ok(Json(logged))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    inbox: String,
    public_key: PublicKey,
    followers: String,
    following: String,
    liked: String,
    outbox: String,
    preferred_username: String,
}

impl Actor {
    fn new(username: String, base: &str, public_key_pem: String) -> Self {
        Actor {
            context: vec![
                "https://www.w3.org/ns/activitystreams".into(),
                "https://w3id.org/security/v1".into(),
            ],
            id: format!("https://{base}/actors/{username}"),
            r#type: "Person".into(),
            inbox: format!("https://{base}/actors/{username}/inbox"),
            public_key: PublicKey {
                id: format!("https://{base}/actors/{username}#main-key"),
                owner: format!("https://{base}/actors/{username}"),
                public_key_pem,
            },
            followers: format!("https://{base}/actors/{username}/followers"),
            following: format!("https://{base}/actors/{username}/following"),
            liked: format!("https://{base}/actors/{username}/liked"),
            outbox: format!("https://{base}/actors/{username}/outbox"),
            preferred_username: username,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    id: String,
    owner: String,
    public_key_pem: String,
}

pub(crate) async fn get_actor(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<JsonLD<Actor>, ActorError> {
    let conn = Connection::open(&state.db_path)?;
    let public_key = match conn.query_row(
        "SELECT public_key FROM Actors where username=?1",
        [&username],
        |row| row.get(0),
    ) {
        Ok(data) => data,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(ActorError::UnknownActor(username))
        }
        Err(err) => return Err(ActorError::Internal(anyhow!(err))),
    };
    Ok(JsonLD(Actor::new(username, &state.base, public_key)))
}

fn token(state: &AppState, web_id: &str) -> Result<String> {
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = Claims {
        exp: iat + (30 * 60),
        iat,
        sub: web_id.to_string(),
        web_id: web_id.to_string(),
    };
    let mut header = Header::new(Algorithm::RS256);
    let key = state.active_key();
    header.kid = Some(key.name.clone());
    let token = encode(&header, &claims, &key.encoding)?;
    Ok(token)
}
