use clap::Parser;

/// DNS-aware XDP rate limiter (subcommands land in Part 2).
#[derive(Parser)]
#[command(name = "segfault", version, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!(
        "segfault {} (pin dir {})",
        segfault_core::version(),
        segfault_core::PIN_DIR
    );
}
