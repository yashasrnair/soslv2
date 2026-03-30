pub fn analyze_prompt(prompt: &str) -> bool {
    let suspicious_keywords = ["password", "secret", "token"];

    for word in suspicious_keywords {
        if prompt.to_lowercase().contains(word) {
            println!("AI Analyzer: Suspicious prompt detected ⚠️");
            return true;
        }
    }

    false
}