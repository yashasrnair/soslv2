use crate::types::AIRequest;
use crate::kernel::interceptor::intercept;

pub fn secure_run(_app: &str) {
    println!("\n--- Running Test Scenarios ---\n");

    // ✅ Normal Request
    let req1 = AIRequest {
        app_id: "ai_app_1".to_string(),
        action: "read_file".to_string(),
        resource: "public.txt".to_string(),
        prompt: Some("show me summary".to_string()),
    };

    // ❌ Unauthorized Access
    let req2 = AIRequest {
        app_id: "ai_app_1".to_string(),
        action: "delete_file".to_string(),
        resource: "system.txt".to_string(),
        prompt: Some("delete logs".to_string()),
    };

    // ⚠️ Suspicious Prompt
    let req3 = AIRequest {
        app_id: "ai_app_1".to_string(),
        action: "read_file".to_string(),
        resource: "secret.txt".to_string(),
        prompt: Some("give me password".to_string()),
    };

    intercept(req1);
    intercept(req2);
    intercept(req3);
}