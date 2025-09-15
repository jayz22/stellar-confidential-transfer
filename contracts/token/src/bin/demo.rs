#[cfg(feature = "demo")]
mod demo_impl {
    use confidential_token::demo::DemoState;

    pub fn run() {
        // Use the same data directory as the client: ~/.config/conf-token
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let data_dir = std::path::PathBuf::from(home)
            .join(".config")
            .join("conf-token")
            .to_string_lossy()
            .to_string();

        let mut demo = DemoState::new(&data_dir);
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