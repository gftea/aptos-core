mod traffic_loader;
//---------------------------
use clap::{Parser, Subcommand};
use traffic_loader::LoadTrafficArgs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    MyLoader::parse().run().await
}


#[derive(Parser)]
#[command(name = "myloader")]
pub struct MyLoader {
    #[command(subcommand)]
    pub subcommand: LoaderCommands,
}

#[derive(Subcommand)]
pub enum LoaderCommands {
    Load(LoadTrafficArgs),
}

impl MyLoader {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.subcommand {
            LoaderCommands::Load(args) => args.run().await,
        }
    }
}
