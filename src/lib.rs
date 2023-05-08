//! Web service API implementation.

use anyhow::{anyhow, Result};
use axum::{
    routing::{get, post},
    Router,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use http::Method;
use inbox::get_shared_inbox;
use jsonwebtoken::{DecodingKey, EncodingKey};
use openssl::rsa::Rsa;

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use ring::rand::SystemRandom;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::{Any, CorsLayer};
use webfinger::resource;

mod actor;
pub use actor::Claims;
use actor::{create_actor, get_actor, login};
mod inbox;
mod outbox;
use outbox::post_outbox;
mod object;
mod protocol;
use object::get_object;
mod util;

mod webfinger;

pub struct Key {
    pub name: String,
    pub decoding: DecodingKey,
    encoding: EncodingKey,
    pub active: bool,
}

impl Key {
    pub fn from_row<E>(
        row: rusqlite::Result<(String, String, String, bool), E>,
    ) -> Result<(String, Self)>
    where
        E: Into<anyhow::Error>,
    {
        match row {
            Ok((name, d64, e64, active)) => {
                let decoding =
                    DecodingKey::from_rsa_pem(&BASE64_STANDARD_NO_PAD.decode(d64.as_bytes())?)?;
                let encoding =
                    EncodingKey::from_rsa_pem(&BASE64_STANDARD_NO_PAD.decode(e64.as_bytes())?)?;
                Ok((
                    name.clone(),
                    Key {
                        name,
                        decoding,
                        encoding,
                        active,
                    },
                ))
            }
            Err(err) => Err(anyhow!(err)),
        }
    }
}

/// State.
struct AppState {
    base: String,
    pool: Pool<SqliteConnectionManager>,
    random: SystemRandom,
    keys: HashMap<String, Key>,
    // encryption_key: String,
}

impl AppState {
    fn active_key(&self) -> &Key {
        self.keys.values().find(|k| k.active).unwrap()
    }

    fn conn(&self) -> Result<PooledConnection<SqliteConnectionManager>> {
        let conn = self.pool.get()?;
        Ok(conn)
    }
}

fn init_db(pool: &Pool<SqliteConnectionManager>) -> Result<HashMap<String, Key>> {
    let conn = pool.get()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Keys (
       name         TEXT PRIMARY KEY,
       public_key   TEXT,
       private_key  TEXT,
       active BOOL
    )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Actors (
        username     TEXT PRIMARY KEY,
        email        TEXT,
        public_key   TEXT,
        private_key  TEXT,
        salt         TEXT,
        password     TEXT
    )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Outbox (
            username      TEXT REFERENCES Actors (username),
            id            TEXT,
            activity_type TEXT,
            created       INTEGER,
            data          TEXT,
            PRIMARY KEY  (username, id)
    )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Objects (
            username      TEXT REFERENCES Actors (username),
            id            TEXT,
            object_type   TEXT,
            created       INTEGER,
            data          TEXT,
            PRIMARY KEY   (username, id)
    )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Inbox (
            username      TEXT REFERENCES Actors (username),
            id            TEXT,
            activity_type TEXT,
            created       INTEGER,
            data          TEXT,
            PRIMARY KEY   (username, id)
    )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS SharedInbox (
            id            TEXT PRIMARY KEY,
            activity_type TEXT,
            created       INTEGER,
            data          TEXT
    )",
        (),
    )?;

    let mut stmt = conn.prepare("SELECT name,public_key,private_key,active FROM Keys")?;
    let mut keys = stmt
        .query_map((), |row| {
            let name: String = row.get(0)?;
            let d64: String = row.get(1)?;
            let e64: String = row.get(2)?;
            let active = row.get(3)?;
            Ok((name, d64, e64, active))
        })?
        .flat_map(Key::from_row)
        .collect::<HashMap<String, Key>>();
    if !keys.values().any(|k| k.active) {
        let rsa = Rsa::generate(2048)?;
        let private_b64 = BASE64_STANDARD_NO_PAD.encode(rsa.private_key_to_pem()?);
        let public_b64 = BASE64_STANDARD_NO_PAD.encode(rsa.public_key_to_pem()?);
        let decoding = DecodingKey::from_rsa_pem(&rsa.public_key_to_pem()?)?;
        let encoding = EncodingKey::from_rsa_pem(&rsa.private_key_to_pem()?)?;
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let name = format!("k{iat}");
        conn.execute(
            "INSERT INTO Keys (name, public_key, private_key, active) VALUES(?1, ?2, ?3, true)",
            (&name, public_b64, private_b64),
        )?;
        keys.insert(
            name.clone(),
            Key {
                name,
                decoding,
                encoding,
                active: true,
            },
        );
    }

    Ok(keys)
}

/// App routes.
pub fn app(base: &str, db_path: &str) -> Result<Router> {
    let manager = SqliteConnectionManager::file(db_path);
    let pool = r2d2::Pool::new(manager).unwrap();

    let keys = init_db(&pool)?;

    let runner_state = Arc::new(AppState {
        base: base.to_string(),
        pool,
        random: SystemRandom::new(),
        keys,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/actors", post(create_actor))
        .route("/actors/:username", get(get_actor))
        .route("/actors/:username/outbox", post(post_outbox))
        .route(
            "/actors/:username/objects/:object_type/:object_id",
            get(get_object),
        )
        .route("/login", post(login))
        .route("/.well-known/webfinger", get(resource))
        .route("/sharedInbox", get(get_shared_inbox))
        .with_state(runner_state)
        .layer(cors);

    Ok(app)
}
