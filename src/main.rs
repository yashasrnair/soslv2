use std::env;
use std::thread;

mod kernel;
mod security;
mod ai;
mod utils;
mod types;

use kernel::interceptor::intercept;
use kernel::proxy::start_proxy;
use kernel::api::start_api;
use kernel::controller::secure_run;
use types::AIRequest;
use crate::utils::dashboard::start_dashboard;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Zero Trust AI Firewall v3");
        println!("=========================");
        println!("  run <prompt>   — Test a prompt through the engine");
        println!("  test           — Run built-in threat scenario suite");
        println!("  api            — Start engine API (port 5000)");
        println!("  dashboard      — Start Rust dashboard (port 9090)");
        println!("  proxy          — Start HTTP proxy (port 8080)");
        println!("  all            — Start API + dashboard + proxy together");
        println!("  logs           — Print logs.txt");
        println!();
        println!("Rules file: rules/rules.json  (hot-reload — edit anytime)");
        return;
    }

    match args[1].as_str() {
        "run" => {
            if args.len() < 3 {
                println!("Usage: soslv2 run <prompt>");
                return;
            }
            let prompt = args[2..].join(" ");
            intercept(AIRequest {
                app_id:   "cli_user".into(),
                action:   "ai_query".into(),
                resource: "external_llm".into(),
                prompt:   Some(prompt),
            });
        }

        "test" => {
            secure_run("cli");
        }

        "logs" => {
            let content = std::fs::read_to_string("logs.txt")
                .unwrap_or_else(|_| "No logs found.".into());
            println!("{}", content);
        }

        "api" => {
            start_api();
        }

        "dashboard" => {
            start_dashboard();
        }

        "proxy" => {
            start_proxy();
        }

        "all" => {
            println!("Starting all Zero Trust services...");
            let t1 = thread::spawn(start_api);
            let t2 = thread::spawn(start_dashboard);
            let t3 = thread::spawn(start_proxy);
            println!("  API       -> http://localhost:5000/check");
            println!("  Dashboard -> http://localhost:9090");
            println!("  Proxy     -> http://localhost:8080");
            println!("  Rules     -> rules/rules.json (hot-reload ON)");
            println!("Press Ctrl+C to stop.");
            t1.join().unwrap();
            t2.join().unwrap();
            t3.join().unwrap();
        }

        _ => {
            println!("Unknown command. Run without arguments to see usage.");
        }
    }
}