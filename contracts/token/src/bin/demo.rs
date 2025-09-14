#[cfg(feature = "demo")]
mod demo_impl {
    use confidential_token::demo::DemoState;

    pub fn run() {
        let mut demo = DemoState::new(".data");
        demo.run_full_demo();
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
        eprintln!("  cargo run --bin demo --features demo");
        std::process::exit(1);
    }
}