# npvdkgrs

Non-interactive publicly verifiable distributed key generation and resharing algorithm over BLS12-381

## Overview

This library implements a non-interactive publicly verifiable distributed key generation (DKG) and key resharing protocol using the BLS12-381 pairing-friendly elliptic curve. It is built using the [Arkworks](https://arkworks.rs/) library for elliptic curve cryptography.

The protocol allows a group of participants to jointly generate a shared public key and corresponding private key shares, without requiring interactive communication rounds. It also supports resharing to change the set of participants or threshold.

Key features:

- Non-interactive DKG and resharing
- Publicly verifiable
- Secure against malicious adversaries
- Built on Arkworks & round-based model
- DKG is just one round
- Resharing is just one round
- Signing is just one round and is non-interactive
- Asynchronous API

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
npvdkgrs = "0.1.0"
```

## Usage

### Key Generation

```rust
use ark_std::UniformRand;
use npvdkgrs::{keygen, party::KeysharePackage, Keypair, PublicKey};

async fn run_dkg(participants: &[PublicKey], threshold: u16) -> Result<KeysharePackage, Error> {
    let mut rng = rand::thread_rng();
    let my_keypair = Keypair::rand(&mut rng);
    let tracer = None;

    let pkg = keygen::run(
        &mut rng,
        tracer,
        &my_keypair,
        participants,
        threshold,
        party
    ).await?;

    Ok(pkg)
}
```

### Signing

```rust
use npvdkgrs::{sign, Signature};

async fn sign_message(
    keypair: &Keypair,
    pkg: &KeysharePackage,
    participants: &[PublicKey],
    message: &[u8],
) -> Result<Signature, Error> {
    let sig = sign::run(
        None,
        keypair,
        pkg,
        participants,
        message,
        party
    ).await?;

    Ok(sig)
}
```

### Verification

```rust
use npvdkgrs::Signature;

fn verify_signature(signature: &Signature, message: &[u8], public_key: &PublicKey) -> bool {
    signature.verify(message, public_key)
}
```

## Features

- `std`: Use the Rust standard library (enabled by default)
- `parallel`: Enable parallel computation optimizations using Rayon
- `asm`: Use assembly optimizations for improved performance
- `print-trace`: Print debug traces for development and troubleshooting
- `getrandom`: Enable getrandom feature for secure random number generation
- `state-machine`: Enable state machine for round-based protocols

## Security Assumptions

The security of this protocol relies on the following assumptions:

1. The hardness of the Discrete Logarithm problem in BLS12-381.
2. The Random Oracle Model for hash functions.
3. The honesty of at least t+1 participants, where t is the threshold.

For more details on the security proofs and assumptions, please refer to the [NPVDKGRS paper](https://github.com/natrixofficial/npvdkgrs/blob/fb5280af42e97a97fef6e1e652c9bf57d7632d37/math/NPVDKGRS.pdf).

## Performance

Benchmarks for different participant counts and thresholds:

| Participants | Threshold | Key Generation | Signing  |
|--------------|-----------|-----------------|---------|
| 3            | 2          | 64ms            | TBD    |
| 5            | 3          | 186ms           | TBD    |
| 8            | 5          | 550ms           | TBD    |
| 10           | 6          | 950ms            | TBD   |
| 12           | 8          | 1.2s            | TBD    |
| 15           | 10         | 3.0s            | TBD    |
| 18           | 12         | 5.1s            | TBD    |


Note: These benchmarks were run on a machine with M1 Macbook PRO. Your results may vary, see [benches](./benches) dir

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

Please make sure to update tests as appropriate and adhere to the existing coding style.

### Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## References

The protocol is based on the paper:

[NPVDKGRS: Non-Interactive Publicly Verifiable Distributed Key Generation and Resharing over BLS12-381](https://github.com/natrixofficial/npvdkgrs/blob/fb5280af42e97a97fef6e1e652c9bf57d7632d37/math/NPVDKGRS.pdf)

## Acknowledgements

This project makes use of the following libraries:

- [Arkworks](https://arkworks.rs/)
- [round-based](https://crates.io/crates/round-based)

We thank the authors and contributors of these projects for their valuable work.
