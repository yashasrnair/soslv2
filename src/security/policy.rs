use crate::types::AIRequest;

pub fn check_permission(request: &AIRequest) -> bool {
    match request.action.as_str() {
        "ai_query" => true,
        "read_file" => true,
        _ => false,
    }
}