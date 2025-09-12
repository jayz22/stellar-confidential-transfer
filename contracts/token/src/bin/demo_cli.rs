#[cfg(feature = "demo")]
mod demo_impl {
    use confidential_token::demo_simple::run_demo;

    pub fn run() {
        run_demo();
    }
}

fn main() {
    #[cfg(feature = "demo")]
    {
        demo_impl::run();
    }

    #[cfg(not(feature = "demo"))]
    {
        eprintln!("Demo mode not enabled. Please run with:");
        eprintln!("  cargo run --bin demo_cli --features demo");
        std::process::exit(1);
    }
}