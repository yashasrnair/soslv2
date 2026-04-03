use std::fs::OpenOptions;
use std::io::Write;

pub fn log_event(event: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("logs.txt")
        .expect("Failed to open log file");
    writeln!(file, "{}", event).expect("Failed to write log");
    println!("[LOG] {}", event);
}