use std::path::Path;

use activer::app;
use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use tower::ServiceExt;

mod utils;
use utils::check_token;

#[tokio::test]
async fn create_actor_and_login() -> Result<()> {
    tracing_subscriber::fmt::init();
    if Path::new("create_actor_and_login.db").exists() {
        std::fs::remove_file("create_actor_and_login.db")?;
    }
    let test_app = app("example.com", "create_actor_and_login.db")?;
    let response = test_app
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/actors")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "john",
                        "email": "john@example.com",
                        "password": "password1",
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
    assert_eq!(
        "https://example.com/actors/john",
        body.get("webId").unwrap().as_str().unwrap()
    );
    assert_eq!(true, body.get("newUser").unwrap().as_bool().unwrap());
    let token = body.get("token").unwrap().as_str().unwrap();
    check_token(
        "create_actor_and_login.db",
        "https://example.com/actors/john",
        token,
    )?;

    let test_app = app("example.com", "create_actor_and_login.db")?;
    let response = test_app
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "john",
                        "password": "password1",
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
    assert_eq!(
        "https://example.com/actors/john",
        body.get("webId").unwrap().as_str().unwrap()
    );
    assert_eq!(false, body.get("newUser").unwrap().as_bool().unwrap());
    let token = body.get("token").unwrap().as_str().unwrap();
    check_token(
        "create_actor_and_login.db",
        "https://example.com/actors/john",
        token,
    )?;

    Ok(())
}
