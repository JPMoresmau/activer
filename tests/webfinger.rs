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
async fn get_account() -> Result<()> {
    let test_app = TestApp::new("get_account.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/.well-known/webfinger?resource=acct:john@example.com")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "subject": "acct:john@example.com",
            "links": [
                {
                    "rel": "self",
                    "type": "application/ld+json",
                    "href": "https://example.com/actors/john"
                }
            ]
        })
    );
    Ok(())
}

#[tokio::test]
async fn get_account_unknown_host() -> Result<()> {
    let test_app = TestApp::new("get_account_unknown_host.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/.well-known/webfinger?resource=acct:john@example2.com")
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
            "error": "account `john@example2.com` not found",
        })
    );
    Ok(())
}

#[tokio::test]
async fn get_account_unknown_username() -> Result<()> {
    let test_app = TestApp::new("get_account_unknown_username.db")?;
    let _ = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/.well-known/webfinger?resource=acct:jane@example.com")
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
            "error": "account `jane@example.com` not found",
        })
    );
    Ok(())
}

#[tokio::test]
async fn get_account_unknown_resource() -> Result<()> {
    let test_app = TestApp::new("get_account_unknown_resource.db")?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/.well-known/webfinger?resource=something:jane@example.com")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::empty())
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
            "error": "resource `something` not supported",
        })
    );
    Ok(())
}

#[tokio::test]
async fn get_account_wrong_query() -> Result<()> {
    let test_app = TestApp::new("get_account_wrong_query.db")?;

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/.well-known/webfinger?resource=jane@example.com")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::empty())
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
            "error": "query `jane@example.com` not understood",
        })
    );
    Ok(())
}
