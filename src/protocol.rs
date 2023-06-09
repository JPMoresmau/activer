use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use axum::body::HttpBody;
use axum::extract::rejection::BytesRejection;
use axum_core::__composite_rejection as composite_rejection;
use axum_core::__define_rejection as define_rejection;
use axum_core::{
    extract::FromRequest,
    response::{IntoResponse, Response},
    BoxError,
};
use bytes::{BufMut, Bytes, BytesMut};
use http::{
    header::{self, HeaderMap, HeaderValue},
    Request, StatusCode,
};
use mime::Mime;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::util::collect_strings;

pub(crate) const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

pub(crate) const ACTIVITY_STREAMS_NS: &str = "https://www.w3.org/ns/activitystreams";

pub(crate) const LD_CONTENT_TYPE: &str = "application/ld+json";

pub(crate) const LD_CONTENT_TYPE_PROFILE: &str =
    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

pub(crate) const ACTIVITIES: [&str; 9] = [
    "Create", "Update", "Delete", "Follow", "Add", "Remove", "Like", "Block", "Undo",
];

define_rejection! {
    #[status = UNPROCESSABLE_ENTITY]
    #[body = "Failed to deserialize the JSON-LD body into the target type"]
    pub struct JsonLDDataError(Error);
}

define_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to parse the request body as JSON-LD"]
     pub struct JsonLDSyntaxError(Error);
}

define_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Expected request with `Content-Type: application/ld+json`"]
    pub struct MissingJsonLDContentType;
}

composite_rejection! {
    pub enum JsonLDRejection {
        JsonLDDataError,
        JsonLDSyntaxError,
        MissingJsonLDContentType,
        BytesRejection,
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct JsonLD<T>(pub T);

#[async_trait]
impl<T, S, B> FromRequest<S, B> for JsonLD<T>
where
    T: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = JsonLDRejection;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        if json_content_type(req.headers()) {
            let bytes = Bytes::from_request(req, state).await?;
            let deserializer = &mut serde_json::Deserializer::from_slice(&bytes);

            let value = match serde_path_to_error::deserialize(deserializer) {
                Ok(value) => value,
                Err(err) => {
                    let rejection = match err.inner().classify() {
                        serde_json::error::Category::Data => JsonLDDataError::from_err(err).into(),
                        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                            JsonLDSyntaxError::from_err(err).into()
                        }
                        serde_json::error::Category::Io => {
                            if cfg!(debug_assertions) {
                                // we don't use `serde_json::from_reader` and instead always buffer
                                // bodies first, so we shouldn't encounter any IO errors
                                unreachable!()
                            } else {
                                JsonLDSyntaxError::from_err(err).into()
                            }
                        }
                    };
                    return Err(rejection);
                }
            };

            Ok(JsonLD(value))
        } else {
            Err(MissingJsonLDContentType.into())
        }
    }
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let content_type = if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        content_type
    } else {
        return false;
    };

    let content_type = if let Ok(content_type) = content_type.to_str() {
        content_type
    } else {
        return false;
    };

    let mime = if let Ok(mime) = content_type.parse::<Mime>() {
        mime
    } else {
        return false;
    };

    let is_ld_content_type = mime.type_() == "application"
        && mime.subtype() == "ld"
        && mime.suffix().map(|n| n.as_str()) == Some("json");

    let is_activity_content_type = mime.type_() == "application"
        && mime.subtype() == "activity"
        && mime.suffix().map(|n| n.as_str()) == Some("json");

    is_ld_content_type || is_activity_content_type
}

axum_core::__impl_deref!(JsonLD);

impl<T> From<T> for JsonLD<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> IntoResponse for JsonLD<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        match serde_json::to_writer(&mut buf, &self.0) {
            Ok(()) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(LD_CONTENT_TYPE_PROFILE),
                )],
                buf.into_inner().freeze(),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
                )],
                err.to_string(),
            )
                .into_response(),
        }
    }
}

pub(crate) struct Created {
    id: Option<String>,
}

impl Created {
    pub(crate) fn new(id: Option<String>) -> Self {
        Created { id }
    }
}

impl IntoResponse for Created {
    fn into_response(self) -> Response {
        match self.id {
            Some(id) => (
                StatusCode::CREATED,
                [(header::LOCATION, HeaderValue::from_str(&id).unwrap())],
            )
                .into_response(),
            None => StatusCode::CREATED.into_response(),
        }
    }
}

pub(crate) fn recipients(value: &Value) -> Vec<&str> {
    let mut v = Vec::new();
    for field in ["to", "bto", "cc", "bcc"] {
        collect_strings(value, field, &mut v);
    }
    v
}

pub(crate) fn clean(value: &mut Value) {
    if let Some(m) = value.as_object_mut() {
        m.remove("bto");
        m.remove("bcc");
        if let Some(v) = m.get_mut("object") {
            clean(v);
        }
    }
}
pub(crate) fn activity_type(activity: &Value) -> Result<&str> {
    match activity.pointer("/type").and_then(|v| v.as_str()) {
        Some(typ) => Ok(typ),
        None => Err(anyhow!("no `type` found in activity",)),
    }
}

pub(crate) fn object_type(activity: &Value) -> Result<&str> {
    match activity.pointer("/object/type").and_then(|v| v.as_str()) {
        Some(typ) => Ok(typ),
        None => Err(anyhow!(
            "no `/object/type` found in {} activity",
            activity_type(activity)?
        )),
    }
}

pub(crate) fn object_object(activity: &Value) -> Result<&str> {
    match activity.pointer("/object/object").and_then(|v| v.as_str()) {
        Some(typ) => Ok(typ),
        None => Err(anyhow!(
            "no `/object/object` found in {} activity",
            activity_type(activity)?
        )),
    }
}

/*
pub(crate) fn is_public(value: &Value) -> bool{
    recipients(value).iter().any(|r| *r == PUBLIC)
}
 */
