mod tokens;

use std::{path::Path, collections::HashMap};

use activer::app;
use anyhow::{Result, anyhow};
use axum::Router;
use http::{Request, StatusCode};
use hyper::Body;
use openssl::{rsa::Rsa, pkey::{Private, PKey}};
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

pub use tokens::check_token;

pub struct TestApp<'a> {
    pub db_path: &'a str,
}

#[allow(dead_code)]
impl<'a> TestApp<'a> {
    pub fn new(db_path: &'a str) -> Result<Self> {
        if Path::new(db_path).exists() {
            std::fs::remove_file(db_path)?;
        }
        Ok(TestApp { db_path })
    }

    pub fn app(&self) -> Result<Router> {
        let test_app = app("example.com", self.db_path, HashMap::new())?;
        Ok(test_app)
    }

    pub fn app_with_cache(&self, cache: HashMap<String, Value>) -> Result<Router> {
        let test_app = app("example.com", self.db_path, cache)?;
        Ok(test_app)
    }


    pub fn check_token(&self, web_id: &str, token: &str) -> Result<()> {
        check_token(self.db_path, web_id, token)
    }

    pub async fn create_actor(&self, username: &str, email: &str, password: &str) -> Result<Value> {
        let response = self
            .app()?
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/actors")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "username": username,
                            "email": email,
                            "password": password,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let web_id = format!("https://example.com/actors/{username}");
        assert_eq!(&web_id, body.get("webId").unwrap().as_str().unwrap());
        assert!(body.get("newUser").unwrap().as_bool().unwrap());
        let token = body.get("token").unwrap().as_str().unwrap();
        self.check_token(&web_id, token)?;
        Ok(body)
    }

    pub fn private_key(&self, username: &str)-> Result<PKey<Private>> {
        let conn = Connection::open(self.db_path)?;
        match conn.query_row(
            "SELECT private_key FROM Actors where username=?1",
            [&username],
            |row| row.get::<usize, String>(0),
        ) {
            Ok(data) => Ok(PKey::from_rsa(Rsa::private_key_from_pem(data.as_bytes())?)?),
            Err(err) => Err(anyhow!(err)),
        }
    }
}

impl<'a> Drop for TestApp<'a> {
    fn drop(&mut self) {
        match std::fs::remove_file(self.db_path) {
            Ok(_) => {}
            Err(err) => eprintln!("could not delete DB file: {err}"),
        }
    }
}
