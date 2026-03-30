use std::env;

mod kernel;
mod security;
mod ai;
mod utils;
mod types;

use kernel::interceptor::intercept;
use kernel::proxy::start_proxy;
use types::AIRequest;
use kernel::api::start_api;
use crate::utils::dashboard::start_dashboard;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage:");
        println!("secure_ai run <prompt>");
        println!("secure_ai logs");
        return;
    }

    match args[1].as_str() {
        "run" => {
            if args.len() < 3 {
                println!("Usage: secure_ai run <prompt>");
                return;
            }

            let prompt = args[2..].join(" ");

            let request = AIRequest {
                app_id: "cli_user".to_string(),
                action: "ai_query".to_string(),
                resource: "external_llm".to_string(),
                prompt: Some(prompt),
            };

            intercept(request);
        }

        "logs" => {
            let content = std::fs::read_to_string("logs.txt")
                .unwrap_or("No logs found".to_string());
            println!("{}", content);
        }

        "proxy" => {
            start_proxy();
        }

        "api" => {
            start_api();
        }

        "dashboard" => {
            start_dashboard();
        }

        _ => {
            println!("Invalid command");
        }
        
    }
}