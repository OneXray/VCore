#[path = "../cli.rs"]
mod cli;

fn main() -> std::process::ExitCode {
    std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/vcore-cli-notices.txt"
    )));
    cli::entry()
}
