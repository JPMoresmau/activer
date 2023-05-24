use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use maplit::hashmap;
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use tower::ServiceExt;

mod utils;
use utils::TestApp;

#[tokio::test]
async fn follow_accept() -> Result<()> {
    let test_app = TestApp::new("follow_accept")?;
    let v = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;
    let john_token = v.get("token").unwrap().as_str().unwrap();
    let v = test_app
        .create_actor("jane", "jane@example.com", "password1")
        .await?;
    let jane_token = v.get("token").unwrap().as_str().unwrap();

    let body = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Follow",
        "to": ["https://example.com/actors/jane"],
        "object": "https://example.com/actors/jane"
    });

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/actors/john/outbox")
                .header(http::header::AUTHORIZATION, format!("Bearer {john_token}"))
                .header(
                    http::header::CONTENT_TYPE,
                    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                )
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    tokio::task::yield_now().await;

    let john = test_app.get_actor("john").await?;
    let cache = hashmap! {
        "https://example.com/actors/john".to_string() => john.clone(),
    };
    let response = test_app
        .app_with_cache(cache)?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/actors/jane/followers")
                .header(http::header::AUTHORIZATION, format!("Bearer {jane_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""
    );
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let mut body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(1, body.get("totalItems").unwrap().as_i64().unwrap());
    let v = body
        .get_mut("orderedItems")
        .unwrap()
        .as_array_mut()
        .unwrap();
    assert_eq!(1, v.len());
    body = v.pop().unwrap();

    assert_eq!(john, body);

    let jane = test_app.get_actor("jane").await?;
    let cache = hashmap! {
        "https://example.com/actors/jane".to_string() => jane.clone(),
    };
    let response = test_app
        .app_with_cache(cache)?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/actors/john/following")
                .header(http::header::AUTHORIZATION, format!("Bearer {john_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""
    );
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let mut body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(1, body.get("totalItems").unwrap().as_i64().unwrap());
    let v = body
        .get_mut("orderedItems")
        .unwrap()
        .as_array_mut()
        .unwrap();
    assert_eq!(1, v.len());
    body = v.pop().unwrap();

    assert_eq!(jane, body);

    Ok(())
}
