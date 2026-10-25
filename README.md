# Solana FHE Starter

**A local-first starter kit for building privacy-preserving applications on Solana.**

[About](#about) · [Resources](#resources) · [Working with the starter](#working-with-solana-fhe-starter) · [Support](#support)

![status: scaffold](https://img.shields.io/badge/status-scaffold-f0b429)
![runs: locally](https://img.shields.io/badge/runs-locally-3ddc97)

> **Status.** This repository is an early scaffold. The FHE engine, the way the kit runs
> locally, and the starter example are still being chosen. The sections below describe the shape
> they will land in, and nothing here claims a capability that has not shipped yet.

## About

### What is Solana FHE Starter?

**Solana FHE Starter** is a starter kit for building applications that compute on encrypted data
on Solana. Fully Homomorphic Encryption (FHE) lets a program operate on values it can never read:
you encrypt a number, hand the ciphertext to a computation, and decrypt only the result. The
plaintext and the key never leave the device that made them.

FHE is genuinely hard to try. The libraries are research-grade, the demos are usually cloud-side
(which teaches the opposite of the trust model FHE exists for), and a developer who wants to see
it move has to assemble a toolchain before running one addition. This kit is the counter-position:
a small, readable starting point that runs on your own machine, in a browser tab you control, with
the interesting part (the computation on data that is never decrypted) visible.

### Table of contents

- [About](#about)
  - [What is Solana FHE Starter?](#what-is-solana-fhe-starter)
  - [Project structure](#project-structure)
  - [Main features](#main-features)
  - [Use cases](#use-cases)
- [Resources](#resources)
- [Working with Solana FHE Starter](#working-with-solana-fhe-starter)
  - [Prerequisites](#prerequisites)
  - [Quickstart](#quickstart)
  - [Citations](#citations)
  - [Contributing](#contributing)
  - [License](#license)
  - [FAQ](#faq)
- [Support](#support)

### Project structure

The repository is being assembled. The intended layout is:

```text
program/      the on-chain program (Solana)
web/          the local-first workbench the user runs
docs/         guides and reference
scripts/      setup and build helpers
```

Directories are added as each part lands, and this section is replaced with the real contents as
they are committed.

### Main features

- **Runs on your machine.** One command to set up and start, with no hosted service and no
  account. The kit is meant to be something you can read end to end and then break on purpose.
- **FHE where you can see it.** Encrypt a value, compute on the ciphertext, and decrypt the
  result on the same device. The intermediate state is never a plaintext.
- **Solana integration.** The encrypted state and its commitments are coordinated on Solana, so
  the flow from your device to the chain is part of the example rather than hidden behind it.
- **A starting point, not a framework.** The kit is deliberately small. The aim is a base you
  can extend, not an abstraction you have to work around.

The concrete feature set, and the FHE engine it is built on, are finalized with the first
implementation.

### Use cases

FHE on Solana is a fit wherever the value being computed on is sensitive and the computation
still has to be shared:

- **Confidential voting.** Tally votes without revealing any individual ballot.
- **Private balances.** Move value without publishing amounts.
- **Sealed-bid auctions.** Bid without revealing the bid or the winner.
- **Encrypted agent state.** Let a program work on data it is not allowed to read.

## Resources

- `docs/` (this repository): guides and reference, added as the kit is built.
- [Awesome FHE](https://github.com/zama-ai/awesome-zama): a curated list of FHE libraries,
  papers, and projects.

## Working with Solana FHE Starter

### Prerequisites

Finalized with the engine and run-model choices. The goal is that a clean machine needs `git` and
nothing else to start: the setup script installs whatever else is required and prints every
command before it runs it.

### Quickstart

The command set is provisional until the run model is chosen. The intended shape is:

```bash
git clone https://github.com/pionyrtech/solana-fhe-starter
cd solana-fhe-starter
./setup.sh
```

### Citations

To cite this project in academic work:

```bibtex
@Misc{SolanaFHEStarter,
  title        = {{Solana FHE Starter: a local-first starter kit for FHE on Solana}},
  author       = {{Pionyr}},
  year         = {2026},
  note         = {\url{https://github.com/pionyrtech/solana-fhe-starter}}
}
```

### Contributing

This repository lives under the [Pionyr](https://github.com/pionyrtech) organization. A
`CONTRIBUTING.md` describing how to build, test, and change the kit is added alongside the first
implementation.

### License

Not yet chosen. The license is decided before the first release and stated here.

### FAQ

**Is this a wallet?**
No. The kit holds no funds and never asks for a private key it could spend.

**Is the cryptography production-grade?**
No. It is a starter kit for learning and prototyping. The parameters it ships with are not a
reviewed production choice, and it should not protect a real secret.

**Does anything leave my machine?**
The design goal is no. Exactly what does and does not leave the device is stated plainly once the
run model is fixed, including any honest exceptions.

## Support

Give the repository a star if it is useful, and open an issue for bugs, questions, or ideas.

[↑ Back to top](#solana-fhe-starter)
