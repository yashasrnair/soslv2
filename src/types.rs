use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRequest {
    pub app_id:   String,
    pub action:   String,
    pub resource: String,
    pub prompt:   Option<String>,
}

/// A single chat message extracted from an AI site payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role:    String,   // "user" | "assistant" | "system"
    pub content: String,
}

/// What the engine sends back to the Python MITM layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResponse {
    pub decision:   String,        // "ALLOW" | "BLOCK"
    pub risk:       i32,
    pub reasons:    Vec<String>,   // human-readable explanations
    pub categories: Vec<String>,   // triggered rule categories
    pub chat_flags: Vec<ChatFlag>, // per-message flags (if AI chat)
}

/// A flag on a specific chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatFlag {
    pub message_index: usize,
    pub role:          String,
    pub snippet:       String,     // first 120 chars of flagged content
    pub reason:        String,
    pub risk:          i32,
}

/// Scope violation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeViolation {
    pub kind:    String,  // "path_traversal" | "extra_files" | "forbidden_ext"
    pub detail:  String,
    pub risk:    i32,
}