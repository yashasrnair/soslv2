use crate::types::AIRequest;

pub fn calculate_risk(request: &AIRequest) -> i32 {
    let mut score = 0;

    if let Some(prompt) = &request.prompt {
        let p = prompt.to_lowercase();

        if p.contains("password") {
            score += 50;
        }
        if p.contains("secret") {
            score += 40;
        }
        if p.contains("token") {
            score += 30;
        }
    }

    score
}