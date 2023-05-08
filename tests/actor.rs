use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use tower::ServiceExt;

mod utils;
use utils::TestApp;

#[tokio::test]
async fn create_actor_and_login() -> Result<()> {
    let test_app = TestApp::new("create_actor_and_login.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
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
    test_app.check_token("https://example.com/actors/john", token)?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/actors/john")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""
    );
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let mut body: Value = serde_json::from_slice(&body).unwrap();
    let key = body.pointer_mut("/publicKey/publicKeyPem").unwrap().take();
    assert!(key
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PUBLIC KEY-----\nMII"));

    assert_eq!(
        body,
        json!({
            "@context":  ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
            "id": "https://example.com/actors/john",
            "type": "Person",
            "inbox": "https://example.com/actors/john/inbox",
            "sharedInbox": "https://example.com/sharedInbox",
            "publicKey": {
                "id": "https://example.com/actors/john#main-key",
                "owner": "https://example.com/actors/john",
                "publicKeyPem": null,
            },
            "followers": "https://example.com/actors/john/followers",
            "following": "https://example.com/actors/john/following",
            "liked": "https://example.com/actors/john/liked",
            "outbox": "https://example.com/actors/john/outbox",
            "preferredUsername": "john"
        })
    );

    Ok(())
}

#[tokio::test]
async fn create_actor_and_login_fail() -> Result<()> {
    let test_app = TestApp::new("create_actor_and_login_fail.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "john",
                        "password": "password",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error": "login failed",
        })
    );

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "jane",
                        "password": "password1",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error": "login failed",
        })
    );
    Ok(())
}

#[tokio::test]
async fn create_actor_duplicate() -> Result<()> {
    let test_app = TestApp::new("create_actor_duplicate.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error": "username `john` already taken",
        })
    );
    Ok(())
}

#[tokio::test]
async fn get_actor_missing() -> Result<()> {
    let test_app = TestApp::new("get_actor_missing.db")?;
    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/actors/john")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error": "username `john` not found",
        })
    );
    Ok(())
}
