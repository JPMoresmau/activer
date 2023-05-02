use std::collections::HashMap;

use activer::{Claims, Key};
use anyhow::Result;
use jsonwebtoken::{decode, Algorithm, Validation};
use rusqlite::Connection;

pub fn active_key(db_path: &str) -> Result<Key> {
    let conn = Connection::open(db_path)?;
    let mut stmt =
        conn.prepare("SELECT name,public_key,private_key,active FROM Keys WHERE active=true")?;
    let keys = stmt
        .query_map((), |row| {
            let name: String = row.get(0)?;
            let d64: String = row.get(1)?;
            let e64: String = row.get(2)?;
            let active = row.get(3)?;
            Ok((name, d64, e64, active))
        })?
        .flat_map(Key::from_row)
        .collect::<HashMap<String, Key>>();
    Ok(keys.into_values().next().unwrap())
}

pub fn check_token(db_path: &str, web_id: &str, token: &str) -> Result<()> {
    let key = active_key(db_path)?;
    let claims = decode::<Claims>(token, &key.decoding, &Validation::new(Algorithm::RS256))?;
    assert_eq!(web_id, &claims.claims.web_id);
    assert_eq!(web_id, &claims.claims.sub);
    Ok(())
}
