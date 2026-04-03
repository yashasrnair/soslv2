use crate::types::AIRequest;
use crate::security::rules_loader::get_rules;

pub fn check_permission(request: &AIRequest) -> bool {
    let rules = get_rules();
    // Explicitly blocked actions always fail
    if rules.blocked_actions.contains(&request.action) {
        return false;
    }
    // Must be in allowed list
    rules.allowed_actions.contains(&request.action)
}