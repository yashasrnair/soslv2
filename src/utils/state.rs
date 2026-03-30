use std::sync::Mutex;
use lazy_static::lazy_static;
use crate::types::AIRequest;

lazy_static! {
    pub static ref BLOCKED_REQUESTS: Mutex<Vec<AIRequest>> = Mutex::new(Vec::new());
}