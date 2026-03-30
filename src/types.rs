use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRequest {
    pub app_id: String,
    pub action: String,
    pub resource: String,
    pub prompt: Option<String>,
}