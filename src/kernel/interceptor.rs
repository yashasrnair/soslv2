use crate::types::AIRequest;
use crate::security::policy::check_permission;
use crate::security::risk::calculate_risk;
use crate::ai::analyzer::analyze_prompt;
use crate::utils::logger::log_event;

pub fn intercept(request: AIRequest) {
    println!("\n=== Zero Trust Engine ===");

    let allowed = check_permission(&request);
    let risk = calculate_risk(&request);

    let mut suspicious = false;

    if let Some(prompt) = &request.prompt {
        suspicious = analyze_prompt(prompt);
    }

    let mut is_ai = false;
    if let Some(prompt) = &request.prompt {
        if prompt.contains("chat") || prompt.contains("ai") {
            is_ai = true;
        }
    }

    let decision: &str;

    if !allowed || risk > 50 || suspicious {
        println!("[BLOCKED ❌] Sent to approval queue");

        crate::utils::state::BLOCKED_REQUESTS
            .lock()
            .unwrap()
            .push(request.clone());

        decision = "BLOCKED";

    } else {
        println!("[ALLOWED ✅]");
        decision = "ALLOWED";
    }

    println!("Decision: {}", decision);
    println!("AI Traffic: {}", is_ai);

    let log = format!(
        "App: {} | Prompt: {:?} | Risk: {} | Decision: {}",
        request.app_id, request.prompt, risk, decision
    );

    log_event(&log);
}