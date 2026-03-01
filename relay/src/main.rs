#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    tokio::select! {
        result = relay::app::run(args, shutdown_tx.clone()) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down...");
            let _ = shutdown_tx.send(());
            Ok(())
        }
    }
}
