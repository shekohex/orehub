//! OreHub Node CLI library.
#![warn(missing_docs)]

pub use orehub_node::*;

fn main() -> sc_cli::Result<()> {
    command::run()
}
