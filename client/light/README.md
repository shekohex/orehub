<h1 align="center">Orehub Lightclient using subxt</h1>

<p align="center">
    <strong>Rust interface to interact with Orehub nodes</strong>
    <br />
</p>

<br />

### Downloading metadata from a OreHub node

Use the [`subxt-cli`](https://lib.rs/crates/subxt-cli) tool to download the metadata for your target runtime from a node.

1. Install:
```bash
cargo install subxt-cli@0.37.0 --force
```

2. To Save the metadata of `orehub-node`:
Run the release build of the `orehub-node` node:
```bash
./target/release/orehub-node --chain=local --tmp
```

then on another terminal run:

```bash
subxt metadata -f bytes > ./client/light/metadata/testnet-runtime.scale
```

3. Generating the rust bindings code from the metadata:

```bash
subxt codegen --file client/light/metadata/testnet-runtime.scale \
    --crate "::subxt_core" \
    --derive Clone \
    --derive Eq \
    --derive PartialEq | rustfmt --edition=2021 --emit=stdout > client/light/src/testnet_runtime.rs
```

### Notes before publishing a new version

1. Make sure to update the `Cargo.toml` file with the new version number.
2. Make sure to update the `CHANGELOG.md` file with the new version number and the changes made.
3. Make sure to update the `README.md` file with the new version number and the changes made.
4. Make sure that everything is working as expected.
