# OreHub Node

OreHub Node is a Polkadot SDK based blockchain node that is designed to be a decentralized Mining Pool for the [Ore](https://ore.supply) cryptocurrency.

## Project Structure

A Polkadot SDK based project such as this one consists of:

* 💿 a [Node](./node/README.md) - the binary application.
* 🧮 the [Runtime](./runtime/README.md) - the core logic of the blockchain.
* 🎨 the [Pallets](./pallets/README.md) - from which the runtime is constructed.

## Getting Started

* 🦀 The project is using the Rust language.

* 👉 Check the
[Rust installation instructions](https://www.rust-lang.org/tools/install) for your system.

* 🛠️ Depending on your operating system and Rust version, there might be additional
packages required to compile this template - please take note of the Rust compiler output.

### Build

🔨 Use the following command to build the node without launching it:

```sh
cargo build --package orehub-node --release
```

🐳 Alternatively, build the docker image:

```sh
docker build . -t orehub
```

### Single-Node Development Chain

👤 The following command starts a single-node development chain:

```sh
./target/release/orehub-node --dev

# docker version:
docker run --rm orehub --dev
```

Development chains:

* 🧹 Do not persist the state.
* 💰 Are pre-configured with a genesis state that includes several pre-funded development accounts.
* 🧑‍⚖️ One development account (`ALICE`) is used as `sudo` accounts.

### Connect with the Polkadot-JS Apps Front-End

* 🌐 You can interact with your local node using the
hosted version of the [Polkadot/Substrate
Portal](https://polkadot.js.org/apps/#/explorer?rpc=ws://localhost:9944).

* 🪐 A hosted version is also
available on [IPFS](https://dotapps.io/).

* 🧑‍🔧 You can also find the source code and instructions for hosting your own instance in the
[`polkadot-js/apps`](https://github.com/polkadot-js/apps) repository.

## Getting Help

* 🧑‍🏫 To learn about Polkadot in general, [Polkadot.network](https://polkadot.network/) website is a good starting point.

* 🧑‍🔧 For technical introduction, [here](https://github.com/paritytech/polkadot-sdk#-documentation) are
the Polkadot SDK documentation resources.

* 👥 Additionally, there are [GitHub issues](https://github.com/paritytech/polkadot-sdk/issues) and
[Substrate StackExchange](https://substrate.stackexchange.com/).
