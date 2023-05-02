mod tokens;

use std::path::Path;

use activer::app;
use anyhow::Result;
use axum::Router;
pub use tokens::check_token;

pub struct TestApp<'a> {
    pub db_path: &'a str,
}

impl<'a> TestApp<'a> {
    pub fn new(db_path: &'a str) -> Result<Self> {
        if Path::new(db_path).exists() {
            std::fs::remove_file(db_path)?;
        }
        Ok(TestApp { db_path })
    }

    pub fn app(&self) -> Result<Router> {
        let test_app = app("example.com", self.db_path)?;
        Ok(test_app)
    }

    pub fn check_token(&self, web_id: &str, token: &str) -> Result<()> {
        check_token(self.db_path, web_id, token)
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
