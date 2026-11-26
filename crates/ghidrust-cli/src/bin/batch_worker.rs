fn main() {
    if let Err(error) = ghidrust_batch::worker::run_stdio_worker() {
        eprintln!("ghidrust batch worker: {error}");
        std::process::exit(1);
    }
}
