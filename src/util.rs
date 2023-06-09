use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use futures::{future::BoxFuture, FutureExt};
use http::HeaderMap;
use openssl::{
    hash::MessageDigest,
    sign::{Signer, Verifier},
};
use reqwest::Client;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{
    actor::{actor_id, extract_username, private_key, public_key, PrivateKey},
    inbox::{add_inbox, add_shared_inbox},
    protocol::PUBLIC,
    AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct Pagination {
    pub(crate) page: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrderedCollection {
    pub(crate) ordered_items: Vec<Value>,
    pub(crate) total_items: u64,
}

pub(crate) fn collect_strings<'a>(value: &'a Value, field: &str, col: &mut Vec<&'a str>) {
    if let Some(vs) = value.get(field).and_then(Value::as_array) {
        for v in vs {
            if let Some(s) = v.as_str() {
                col.push(s)
            }
        }
    }
    if let Some(s) = value.get(field).and_then(Value::as_str) {
        col.push(s);
    }
}

pub(crate) fn copy(from: &Value, to: &mut Value, fields: &[&str]) {
    for field in fields {
        if let Some(value) = from.get(field) {
            to.as_object_mut()
                .unwrap()
                .insert(field.to_string(), value.clone());
        }
    }
}

pub(crate) async fn get(state: &AppState, url: &str, pointer: Option<&str>) -> Result<Value> {
    let mut v = match state.cache.get(url) {
        Some(v) => v.clone(),
        None => serde_json::from_slice(&reqwest::get(url).await?.bytes().await?)?,
    };
    if let Some(p) = pointer {
        v = v
            .pointer_mut(p)
            .ok_or_else(|| anyhow!("{p} not found in value"))?
            .take();
    }
    Ok(v)
}

pub(crate) async fn post(
    state: &AppState,
    actor_id: &str,
    key: &PrivateKey,
    data: &Value,
) -> Result<()> {
    let inbox = get(state, actor_id, Some("/inbox")).await?;
    let inbox = inbox
        .as_str()
        .ok_or_else(|| anyhow!("inbox not a string"))?;
    let data = serde_json::to_vec(data)?;
    let parsed = Url::parse(inbox)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("no host in inbox url"))?;
    let path = parsed.path();
    let date = chrono::Utc::now().to_rfc2822();
    let digest = digest(&SHA256, &data);
    let digest = format!("sha-256={}", BASE64_STANDARD.encode(digest));
    let to_sign =
        format!("(request-target): post {path}\nhost: {host}\ndate: {date}\ndigest: {digest}\n");
    let mut signer = Signer::new(MessageDigest::sha256(), &key.key)?;
    signer.update(to_sign.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    let signature = format!(
        "keyId=\"{}\",headers=\"(request-target) host date digest\",signature=\"{}\"",
        key.id,
        BASE64_STANDARD.encode(signature)
    );
    Client::new()
        .post(inbox)
        .header("Date", date)
        .header("Digest", digest)
        .header("Signature", signature)
        .body(data)
        .send()
        .await?;
    Ok(())
}

pub(crate) async fn verify(
    state: &AppState,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    data: &Value,
) -> Result<bool> {
    let data = serde_json::to_vec(data)?;
    let digest = digest(&SHA256, &data);
    let digest = format!("sha-256={}", BASE64_STANDARD.encode(digest));

    if let Some(d) = headers.get("digest") {
        if d.to_str()? != digest {
            return Err(anyhow!("wrong digest"));
        }
    }
    let s = headers
        .get("signature")
        .ok_or_else(|| anyhow!("no signature"))?;
    let m = parse_map(s.to_str()?);
    let key_id = m
        .get("keyId")
        .ok_or_else(|| anyhow!("no keyId in signature"))?;
    let signature = BASE64_STANDARD.decode(
        m.get("signature")
            .ok_or_else(|| anyhow!("no signature in signature"))?,
    )?;
    let mut sign_data = String::new();
    for header_to_check in m
        .get("headers")
        .ok_or_else(|| anyhow!("no headers in signature"))?
        .split(' ')
    {
        let header_value = if header_to_check == "(request-target)" {
            format!("{method} {path}")
        } else {
            headers
                .get(header_to_check)
                .ok_or_else(|| anyhow!("missing header {header_to_check}"))?
                .to_str()?
                .to_string()
        };
        sign_data.push_str(&format!("{header_to_check}: {header_value}\n"));
    }
    let pkey = public_key(state, key_id).await?;
    let mut verif = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verif.update(sign_data.as_bytes())?;
    let ok = verif.verify(&signature)?;
    Ok(ok)
}

fn parse_map(value: &str) -> HashMap<&str, &str> {
    let mut m = HashMap::new();
    for d in value.split(',') {
        if let Some((name, val)) = d.split_once('=') {
            m.insert(name, unquote(val));
        }
    }
    m
}

fn unquote(value: &str) -> &str {
    value.trim_matches('"')
}

pub fn value_from_row<E>(row: rusqlite::Result<Value, E>) -> Result<Value>
where
    E: Into<anyhow::Error>,
{
    match row {
        Ok(value) => Ok(value),
        Err(err) => Err(anyhow!(err)),
    }
}

pub fn string_from_row<E>(row: rusqlite::Result<String, E>) -> Result<String>
where
    E: Into<anyhow::Error>,
{
    match row {
        Ok(value) => Ok(value),
        Err(err) => Err(anyhow!(err)),
    }
}

pub(crate) async fn trigger_send_to_recipient(
    state: Arc<AppState>,
    username: &str,
    recipient: String,
    activity_id: Arc<String>,
    activity: Arc<Value>,
    iat: i64,
) -> Result<()> {
    let actor_id = Arc::new(actor_id(&state, username));
    let key = Arc::new(private_key(&state, username)?);
    tokio::spawn({
        let aid = activity_id.clone();
        async move {
            match send_to_recipient(state, recipient.clone(), actor_id, key, aid, activity, iat)
                .await
            {
                Ok(_) => {
                    tracing::info!("Sent activity {activity_id} to {recipient}")
                }
                Err(err) => {
                    tracing::error!("Sending activity {activity_id} to {recipient} failed: {err}")
                }
            };
        }
    });

    Ok(())
}

pub(crate) fn send_to_recipient(
    state: Arc<AppState>,
    recipient: String,
    actor_id: Arc<String>,
    key: Arc<PrivateKey>,
    activity_id: Arc<String>,
    activity: Arc<Value>,
    iat: i64,
) -> BoxFuture<'static, Result<()>> {
    async move {
        let ac = Arc::clone(&activity);
        let activity_type = ac
            .get("type")
            .ok_or_else(|| anyhow!("no activity type"))?
            .as_str()
            .ok_or_else(|| anyhow!("activity type not a string"))?;
        if recipient == PUBLIC {
            add_shared_inbox(&state, &activity_id, activity_type, &activity, iat)?;
        } else if recipient != *actor_id {
            match extract_username(&state, &recipient) {
                Some(rec_username) => {
                    add_inbox(
                        state,
                        &rec_username,
                        &activity_id,
                        activity_type,
                        activity,
                        iat,
                    )
                    .await?;
                }
                None => {
                    post(&state, &recipient, &key, &activity).await?;
                }
            }
        }
        Ok(())
    }
    .boxed()
}
