use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use chrono::{DateTime, Utc};
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use tower::ServiceExt;

mod utils;
use utils::TestApp;

#[tokio::test]
async fn create_note() -> Result<()> {
    test_note_creation(
        "create_note.db",
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
        true,
    )
    .await
}

#[tokio::test]
async fn create_note_no_profile() -> Result<()> {
    test_note_creation("create_note_no_profile.db", "application/ld+json", true).await
}

#[tokio::test]
async fn create_note_no_wrapping() -> Result<()> {
    test_note_creation(
        "create_note_no_wrapping.db",
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
        false,
    )
    .await
}

async fn test_note_creation(db_path: &str, content_type: &str, wrapping: bool) -> Result<()> {
    let test_app = TestApp::new(db_path)?;
    let v = test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;
    let token = v.get("token").unwrap().as_str().unwrap();

    let mut body = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "content": "First post!"
    });
    if wrapping {
        body = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Create",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "object": body,
        });
    }
    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/actors/john/outbox")
                .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(http::header::CONTENT_TYPE, content_type)
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response.headers().get("location").unwrap().to_str()?;
    assert!(location.starts_with("https://example.com/actors/john/objects/note/"));
    //eprintln!("{location} {}", location.strip_prefix("https://example.com").unwrap());
    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri(location.strip_prefix("https://example.com").unwrap())
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
    let published = body
        .pointer_mut("/published")
        .unwrap()
        .take()
        .as_str()
        .unwrap()
        .to_string();
    let published = DateTime::parse_from_rfc3339(&published)?;
    assert!((published.timestamp() - Utc::now().timestamp()).abs() < 2);
    assert_eq!(
        body,
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": location,
            "attributedTo": "https://example.com/actors/john",
            "type": "Note",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "content": "First post!",
            "published": null,
        })
    );

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/sharedInbox")
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

    assert_eq!(
        "https://www.w3.org/ns/activitystreams",
        body.get("@context").unwrap().as_str().unwrap()
    );
    assert_eq!("Create", body.get("type").unwrap().as_str().unwrap());
    let mut object = body.pointer_mut("/object").unwrap().take();
    let published = object
        .pointer_mut("/published")
        .unwrap()
        .take()
        .as_str()
        .unwrap()
        .to_string();
    let published = DateTime::parse_from_rfc3339(&published)?;
    assert!((published.timestamp() - Utc::now().timestamp()).abs() < 2);
    assert_eq!(
        object,
        json!({
            "id": location,
            "attributedTo": "https://example.com/actors/john",
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Note",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "content": "First post!",
            "published": null,
        })
    );

    Ok(())
}

#[tokio::test]
async fn test_note_creation_protect() -> Result<()> {
    let test_app = TestApp::new("test_note_creation_protect")?;
    test_app
        .create_actor("john", "john@example.com", "password1")
        .await?;
    let v = test_app
        .create_actor("jane", "jane@example.com", "password1")
        .await?;
    let token = v.get("token").unwrap().as_str().unwrap();

    let body = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "content": "First post!"
    });

    let response = test_app
        .app()?
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/actors/john/outbox")
                .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    http::header::CONTENT_TYPE,
                    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                )
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error":  "can only post to own outbox",
        })
    );
    Ok(())
}
