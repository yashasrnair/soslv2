use std::env;
use std::thread;

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
        println!("  soslv2 run <prompt>      — Intercept a CLI prompt");
        println!("  soslv2 logs              — View logs");
        println!("  soslv2 proxy             — Start HTTP proxy (port 8080)");
        println!("  soslv2 api               — Start Zero-Trust API (port 5000)");
        println!("  soslv2 dashboard         — Start dashboard (port 9090)");
        println!("  soslv2 all               — Start API + Dashboard + Proxy together");
        return;
    }

    match args[1].as_str() {
        "run" => {
            if args.len() < 3 {
                println!("Usage: soslv2 run <prompt>");
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
                .unwrap_or_else(|_| "No logs found".to_string());
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

        // 🔥 NEW: run all three servers at once in separate threads
        "all" => {
            println!("🚀 Starting all services...");

            let api_thread = thread::spawn(|| {
                start_api();
            });

            let dashboard_thread = thread::spawn(|| {
                start_dashboard();
            });

            let proxy_thread = thread::spawn(|| {
                start_proxy();
            });

            println!("✅ API       → http://localhost:5000/check");
            println!("✅ Dashboard → http://localhost:9090");
            println!("✅ Proxy     → http://localhost:8080");
            println!("Press Ctrl+C to stop.");

            // Wait for all threads (they run indefinitely)
            api_thread.join().unwrap();
            dashboard_thread.join().unwrap();
            proxy_thread.join().unwrap();
        }

        _ => {
            println!("Invalid command. Run without arguments to see usage.");
        }
    }
}