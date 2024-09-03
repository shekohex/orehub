# OreHub: A Decentralized Mining Pool for Ore Cryptocurrency

## Abstract

This paper proposes OreHub, a novel decentralized mining pool architecture for the Ore cryptocurrency. Ore, a proof-of-work token built on the Solana network, utilizes DrillX, a unique mining algorithm that enables mining on consumer-grade hardware and implements non-exclusive rewards. OreHub leverages a Substrate-based sidechain in conjunction with a Solana program to create a peer-to-peer mining pool that maintains decentralization while providing the benefits of pooled mining. The system employs distributed key generation (DKG) using the FROST protocol for enhanced security. This paper outlines the technical architecture, operational flow, and potential benefits of the OreHub system, as well as discussing challenges and areas for future research.

## 1. Introduction

### 1.1 Background on Ore Cryptocurrency

Ore is a proof-of-work cryptocurrency built on the Solana network, designed with the following key features:

- Mineable on everyday devices (laptops, phones, home computers)
- Fixed total supply of 21 million tokens
- Steady issuance rate of one token per minute
- Novel fair mining protocol with non-exclusive rewards
- Mining algorithm called DrillX, built on top of Equix (which is based on Equihash and HashX)

### 1.2 The Need for Decentralized Mining Pools

While Ore's design allows for individual mining, pooled mining offers several advantages, including more consistent rewards for miners. However, traditional centralized mining pools introduce single points of failure and potential centralization risks. This paper proposes OreHub, a decentralized mining pool solution that aims to provide the benefits of pooled mining while maintaining the decentralized ethos of cryptocurrencies.

## 2. OreHub Architecture

OreHub consists of two main components:

1. OreHub Sidechain: A Substrate-based blockchain
2. Pool Program: A Solana program for managing pool operations

### 2.1 OreHub Sidechain

The OreHub sidechain is built using the Substrate framework and serves as the coordination layer for the decentralized mining pool. Key features include:

- Tracking miner rewards
- Managing a set of validators that participate in DKG
- Generating signatures for pool operations using FROST protocol with a TSS.
- Aura consensus with Grandpa finality
- On-chain governance using the Democracy pallet
- Treasury for community funding and project support

### 2.2 Pool Program (Solana)

The Pool Program is deployed on the Solana network and interfaces with the Ore program. Its responsibilities include:

- Managing the pool's mining account on the Ore program
- Verifying and submitting mining solutions
- Claiming and distributing rewards
- Interfacing with the OreHub sidechain through a governor account

## 3. Security Model

### 3.1 Threshold Signature Scheme (TSS)

OreHub employs a threshold signature scheme as part of its distributed key generation (DKG) process. The system uses a 2/3 threshold, which significantly enhances its security properties:

- Let $n$ be the total number of participants in the DKG.
- The threshold $t$ is set such that $t > \frac{2n}{3}$.
- For any signing operation, at least $t$ participants must cooperate.

This threshold ensures that:

1. As long as more than 1/3 of the participants are honest, the system remains secure.
2. An attacker would need to control more than 2/3 of the participants to compromise the system.

This security model provides robust protection against various attacks, including traditional 51% attacks, and aligns with Byzantine Fault Tolerant (BFT) consensus mechanisms.

## 4. Operational Flow

The OreHub system operates through a series of steps involving both the sidechain and the Solana program:

1. Initialization
2. Mining process
3. Solution submission and verification
4. Reward distribution
5. Payout process

### 4.1 Initialization

1. The Pool Program is deployed on Solana and initializes a mining account with the Ore program.
2. A governor account is established using DKG among OreHub validators.

### 4.2 Mining Process

1. Miners download the OreHub node software and generate Ed25519 keys.
2. Miners retrieve the current challenge from on-chain data.
3. Off-chain workers (OCWs) begin mining using the DrillX algorithm.

### 4.3 Solution Submission and Verification

1. Miners submit solutions to the OreHub chain via extrinsics.
2. The mining pallet validates solutions and selects the best one.
3. A Solana transaction is generated and signed by the governor account using DKG.
4. The signed transaction is submitted to the Pool Program on Solana.

### 4.4 Reward Distribution

1. The Pool Program verifies the transaction and submits it to the Ore program.
2. Ore program verifies the solution and rewards the pool.
3. Transaction results are sent back to OreHub for verification.
4. OreHub distributes rewards to participating miners based on their contributions.

### 4.5 Payout Process

1. Miners request payouts through OreHub extrinsics.
2. A Solana transaction is generated and signed by the governor account.
3. Miners submit the signed transaction to the Pool Program.
4. The Pool Program claims Ore tokens and transfers them to the miner's Solana account.

## 5. Technical Innovations

### 5.1 Distributed Key Generation (DKG)

OreHub utilizes the FROST (Flexible Round-Optimized Schnorr Threshold) protocol for distributed key generation among validators. This ensures that no single entity has control over the pool's operations.

### 5.2 Cross-Chain Communication

The system implements a novel cross-chain communication mechanism between the Substrate-based OreHub and the Solana network, enabling seamless operation of the decentralized pool.

### 5.3 Gassless Transactions

OreHub implements a fee structure that allows for gassless mining-related transactions, lowering the barrier to entry for miners.

## 6. Security Considerations

### 6.1 Validator Selection

Validators are selected using the standard staking pallet. Users can lock up their ORE tokens as collateral to become validators. The more tokens locked up, the higher the chance of being selected as a validator. This is a common method used in proof-of-stake blockchains to secure the network.

### 6.2 Guardian Selection

Guardians are participants in the DKG process, which is critical for generating distributed keys used in the OreHub-Solana connection. Guardians are selected based on the following criteria:

1. Must be in the active set of validators
2. Selected by the DKG Pallet based on:
   - Amount of ORE tokens locked in the staking pallet
   - Duration as a validator
   - Duration as a guardian

### 6.3 Slashing Mechanisms

The system implements slashing for spamming or submitting invalid solutions, discouraging malicious behavior.

### 6.4 Multi-Signature Operations

Critical operations require multi-signature approval through the DKG mechanism, enhancing security.

## 7. Economic Model

### 7.1 Token Economics

OreHub uses Ore as its native token, minting new tokens only when the pool is rewarded and burning them during payouts.

### 7.2 Fee Structure

Most transactions on OreHub are feeless, with a small fixed fee applied only to payout transactions.

### 7.3 Treasury

A portion of fees and donations are directed to a treasury, funding ongoing development and community initiatives.

### 7.4 Reward Distribution

Rewards are distributed among miners, validators, and guardians based on their contributions:

- Miners: Rewarded based on their last N difficulty shares (e.g., last 6 hours of shares)
- Validators: Rewarded based on their era points
- Guardians: Rewarded based on their contribution to the DKG process

The exact distribution mechanism is still being refined to ensure fair and transparent reward allocation.

## 8. Cross-Chain Operations

### 8.1 OreHub to Solana Connection

1. After the Genesis DKG process, the shared Public Key (ed25519 share public key) is added to the Pool Program on Solana.
2. Transactions are generated on OreHub and signed using the threshold signature scheme (TSS).
3. A relayer system sends the signed transaction to the Pool program on Solana.
4. The Pool program executes the transaction after verifying the governor account's signature.

### 8.2 Solana to OreHub Connection

1. The Pool program on Solana returns transaction results as program logs.
2. A relayer submits the transaction hash to OreHub for verification.
3. Guardians verify the transaction hash and its result.
4. If the majority of guardians agree, the result is saved on OreHub using a threshold signature scheme (TSS).

## 9. Detailed Mining Process

1. Genesis:
   - Initial validators and guardians are set up by the OreHub team.
   - DKG process generates a shared public key.
   - Guardians sign a transaction to initialize the Pool program on Solana.

2. Pool Initialization:
   - A relayer sends the initialization transaction to Solana.
   - The Pool program creates an Ore mining account and returns challenge information.

3. Transaction Verification:
   - Relayer submits the transaction hash to OreHub.
   - Guardians verify the transaction and its result.

4. Mining:
   - Miners submit solutions to the OreHub mining pallet.
   - Validators verify solutions and include them in blocks.
   - Incorrect solutions result in penalties for miners and rewards for validators.

5. Reward Claiming:
   - At the end of each mining round, the highest difficulty solution is selected.
   - A transaction is created and signed by guardians to claim the reward on Solana.
   - The signed transaction is sent to the Pool program on Solana by a relayer.

6. Result Verification:
   - The Pool program executes the transaction and returns the result.
   - Guardians verify the transaction hash and its result on OreHub.

7. Reward Distribution:
   - Rewards are recorded on-chain and distributed at the end of each epoch.

## 10. Challenges and Future Work

### 10.1 Scalability

As the number of miners grows, ensuring efficient operation of the DKG protocol and timely transaction processing will be crucial.

### 10.2 Cross-Chain Reliability

Maintaining consistent state between OreHub and Solana in the face of network issues or attacks requires robust mechanisms.

### 10.3 Incentive Alignment

Further research is needed to ensure that the incentive structure encourages participation and honest behavior across all roles in the system.

## 11. Conclusion

OreHub presents a novel approach to decentralized mining pools, leveraging the strengths of both Substrate and Solana ecosystems. By combining proof-of-work mining with distributed key generation and cross-chain operations, OreHub aims to provide a secure, fair, and efficient pooled mining experience for Ore cryptocurrency. The use of a 2/3 threshold for the TSS in the DKG provides strong security guarantees, requiring an attacker to control a supermajority of the pool's hash power to compromise the system. While challenges remain, particularly in scalability and cross-chain reliability, the proposed system offers a promising direction for decentralized infrastructure in the cryptocurrency space.

## 12. FAQs and Open Questions

1. Q: How does OreHub ensure fair distribution of rewards among miners?
   A: This requires further research and potentially the implementation of a verifiable random function (VRF) for reward distribution.

2. Q: What measures are in place to prevent a Sybil attack on the validator selection process?
   A: While the PoW requirement provides some protection, additional mechanisms may be needed to ensure long-term resilience against such attacks.

3. Q: How can the system handle temporary network partitions between OreHub and Solana?
   A: Developing robust reconciliation mechanisms for cross-chain state is an important area for future work.

4. Q: What is the optimal number of validators for balancing security and efficiency in the DKG process?
   A: This requires empirical testing and theoretical analysis to determine the best trade-off.

5. Q: How can the system be made more resistant to potential vulnerabilities in the Solana network?
   A: Implementing additional verification layers or considering a multi-chain approach could enhance overall system security.

6. Q: What are the legal and regulatory implications of operating a decentralized mining pool across multiple blockchain networks?
   A: This requires careful legal analysis and potentially engaging with regulatory bodies to ensure compliance.

7. Q: How can the user experience be optimized to make participation in OreHub accessible to non-technical users?
   A: Developing user-friendly interfaces and simplified onboarding processes is crucial for widespread adoption.

8. Q: What mechanisms can be implemented to encourage long-term commitment from miners and prevent frequent switching between pools?
   A: Exploring reputation systems or time-locked rewards could provide incentives for sustained participation.

9. Q: How does the DrillX algorithm compare to other ASIC-resistant mining algorithms in terms of performance and security?
   A: Further research is needed to comprehensively compare DrillX with other algorithms like RandomX or ProgPoW, particularly in the context of Solana's execution environment.

These questions highlight areas where further research, development, and community discussion are needed to refine and improve the OreHub concept.

## 13. References

1. [Ore](https://ore.supply/)
2. [Solana](https://solana.com/)
3. [Substrate](https://substrate.dev/)
4. [FROST](https://eprint.iacr.org/2020/852.pdf)
5. [Verifiable Random Functions](https://en.wikipedia.org/wiki/Verifiable_random_function)
6. [ASIC](https://en.wikipedia.org/wiki/Application-specific_integrated_circuit)
7. [Proof-of-Work](https://en.bitcoinwiki.org/wiki/Proof-of-Work)
8. [Threshold Signature Schemes](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
9. [DKG](https://en.wikipedia.org/wiki/Distributed_key_generation)
10. [51% Attack](https://en.bitcoinwiki.org/wiki/51%25_attack)
