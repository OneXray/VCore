#[path = "../cli.rs"]
mod cli;

fn main() -> std::process::ExitCode {
    vole::release_notices::retain();
    cli::entry()
}
