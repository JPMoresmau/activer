use serde::{Deserialize, Serialize};
use serde_json::Value;

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
