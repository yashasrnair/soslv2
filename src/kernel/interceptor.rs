use crate::types::AIRequest;
use crate::security::policy::check_permission;
use crate::security::risk::calculate_risk;
use crate::security::rules_loader::get_rules;
use crate::ai::analyzer::analyze_prompt;
use crate::utils::logger::log_event;

pub fn intercept(request: AIRequest) {
    println!("\n=== Zero Trust Engine ===");

    let rules      = get_rules();
    let allowed    = check_permission(&request);
    let risk_res   = calculate_risk(&request);
    let suspicious = request.prompt.as_deref().map(analyze_prompt).unwrap_or(false);
    let total_risk = risk_res.score;

    let decision = if !allowed || total_risk >= rules.thresholds.block_score || suspicious {
        println!("[BLOCKED] risk={} categories={:?}", total_risk, risk_res.categories);
        for r in &risk_res.reasons {
            println!("  * {}", r);
        }
        crate::utils::state::BLOCKED_REQUESTS
            .lock().unwrap()
            .push(request.clone());
        "BLOCKED"
    } else {
        println!("[ALLOWED] risk={}", total_risk);
        "ALLOWED"
    };

    log_event(&format!(
        "App:{} | Risk:{} | Categories:{} | Decision:{}",
        request.app_id,
        total_risk,
        risk_res.categories.join(","),
        decision
    ));
}