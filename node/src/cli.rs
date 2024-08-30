use sc_cli::RunCmd;

#[cfg(feature = "manual-seal")]
#[derive(Debug, Clone)]
pub enum Consensus {
    ManualSeal(u64),
    InstantSeal,
}

#[cfg(feature = "manual-seal")]
impl std::str::FromStr for Consensus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "instant-seal" {
            Consensus::InstantSeal
        } else if let Some(block_time) = s.strip_prefix("manual-seal-") {
            Consensus::ManualSeal(block_time.parse().map_err(|_| "invalid block time")?)
        } else {
            return Err("incorrect consensus identifier".into());
        })
    }
}

#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[cfg(feature = "manual-seal")]
    #[clap(long, default_value = "manual-seal-3000")]
    pub consensus: Consensus,

    #[clap(flatten)]
    pub run: RunCmd,
}

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommand {
    /// Key management cli utilities
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),
    /// Sub-commands concerned with benchmarking.
    #[command(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
    /// Bag threshold generation script for pallet-bag-list.
    GenerateBags(GenerateBagsCmd),
}

#[derive(Debug, clap::Parser)]
pub struct GenerateBagsCmd {
    /// How many bags to generate.
    #[arg(long, default_value_t = 200)]
    n_bags: usize,

    /// Where to write the output.
    output: std::path::PathBuf,

    /// The total issuance of the currency used to create `VoteWeight`.
    #[arg(short, long)]
    total_issuance: u128,

    /// The minimum account balance (i.e. existential deposit) for the currency used to create
    /// `VoteWeight`.
    #[arg(short, long)]
    minimum_balance: u128,
}

impl GenerateBagsCmd {
    pub fn run(&self) -> Result<(), String> {
        if cfg!(not(feature = "generate-bags")) {
            return Err("This command is only available in the `generate-bags` feature.".into());
        } else {
            #[cfg(feature = "generate-bags")]
            crate::generate_bags::generate_thresholds::<orehub_runtime::Runtime>(
                self.n_bags,
                &self.output,
                self.total_issuance,
                self.minimum_balance,
            )
            .map_err(|e| format!("{:?}", e))?;
            Ok(())
        }
    }
}
