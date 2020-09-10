<div align="center">
  <h1>Magical Bitcoin Library</h1>

  <img src="./static/wizard.svg" width="220" />

  <p>
    <strong>A modern, lightweight, descriptor-based wallet library written in Rust!</strong>
  </p>

  <p>
    <!-- <a href="https://crates.io/crates/magical"><img alt="Crate Info" src="https://img.shields.io/crates/v/magical.svg"/></a> -->
    <a href="https://travis-ci.org/MagicalBitcoin/magical-bitcoin-wallet"><img alt="Traivs Status" src="https://travis-ci.org/MagicalBitcoin/magical-bitcoin-wallet.svg?branch=master"></a>
    <a href="https://magicalbitcoin.org/docs-rs/magical"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-magical-green"/></a>
    <a href="https://blog.rust-lang.org/2020/07/16/Rust-1.45.0.html"><img alt="Rustc Version 1.45+" src="https://img.shields.io/badge/rustc-1.45%2B-lightgrey.svg"/></a>
  </p>

  <h4>
    <a href="https://magicalbitcoin.org">Project Homepage</a>
    <span> | </span>
    <a href="https://magicalbitcoin.org/docs-rs/magical">Documentation</a>
  </h4>
</div>

## About

The `magical` library aims to be the core building block for Bitcoin wallets of any kind.

* It uses [Miniscript](https://github.com/rust-bitcoin/rust-miniscript) to support descriptors with generalized conditions. This exact same library can be used to build
  single-sig wallets, multisigs, timelocked contracts and more.
* It supports multiple blockchain backends and databases, allowing developers to choose exactly what's right for their projects.
* It's built to be cross-platform: the core logic works on desktop, mobile, and even WebAssembly.
* It's very easy to extend: developers can implement customized logic for blockchain backends, databases, signers, coin selection, and more, without having to fork and modify this library.

## Examples

### Sync the balance of a descriptor

```no_run
use magical::Wallet;
use magical::database::MemoryDatabase;
use magical::blockchain::{noop_progress, ElectrumBlockchain};

use magical::electrum_client::Client;

fn main() -> Result<(), magical::Error> {
    let client = Client::new("ssl://electrum.blockstream.info:60002", None)?;
    let wallet = Wallet::new(
        "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
        Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
        bitcoin::Network::Testnet,
        MemoryDatabase::default(),
        ElectrumBlockchain::from(client)
    )?;

    wallet.sync(noop_progress(), None)?;

    println!("Descriptor balance: {} SAT", wallet.get_balance()?);

    Ok(())
}
```

### Generate a few addresses

```
use magical::{Wallet, OfflineWallet};
use magical::database::MemoryDatabase;

fn main() -> Result<(), magical::Error> {
    let wallet: OfflineWallet<_> = Wallet::new_offline(
        "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
        Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
        bitcoin::Network::Testnet,
        MemoryDatabase::default(),
    )?;

    println!("Address #0: {}", wallet.get_new_address()?);
    println!("Address #1: {}", wallet.get_new_address()?);
    println!("Address #2: {}", wallet.get_new_address()?);

    Ok(())
}
```

### Create a transaction

```no_run
use magical::{FeeRate, TxBuilder, Wallet};
use magical::database::MemoryDatabase;
use magical::blockchain::{noop_progress, ElectrumBlockchain};

use magical::electrum_client::Client;

use bitcoin::consensus::serialize;

fn main() -> Result<(), magical::Error> {
    let client = Client::new("ssl://electrum.blockstream.info:60002", None)?;
    let wallet = Wallet::new(
        "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
        Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
        bitcoin::Network::Testnet,
        MemoryDatabase::default(),
        ElectrumBlockchain::from(client)
    )?;

    wallet.sync(noop_progress(), None)?;

    let send_to = wallet.get_new_address()?;
    let (psbt, details) = wallet.create_tx(
        TxBuilder::with_recipients(vec![(send_to.script_pubkey(), 50_000)])
            .enable_rbf()
            .do_not_spend_change()
            .fee_rate(FeeRate::from_sat_per_vb(5.0))
    )?;

    println!("Transaction details: {:#?}", details);
    println!("Unsigned PSBT: {}", base64::encode(&serialize(&psbt)));

    Ok(())
}
```

### Sign a transaction

```no_run
use magical::{Wallet, OfflineWallet};
use magical::database::MemoryDatabase;

use bitcoin::consensus::deserialize;

fn main() -> Result<(), magical::Error> {
    let wallet: OfflineWallet<_> = Wallet::new_offline(
        "wpkh([c258d2e4/84h/1h/0h]tprv8griRPhA7342zfRyB6CqeKF8CJDXYu5pgnj1cjL1u2ngKcJha5jjTRimG82ABzJQ4MQe71CV54xfn25BbhCNfEGGJZnxvCDQCd6JkbvxW6h/0/*)",
        Some("wpkh([c258d2e4/84h/1h/0h]tprv8griRPhA7342zfRyB6CqeKF8CJDXYu5pgnj1cjL1u2ngKcJha5jjTRimG82ABzJQ4MQe71CV54xfn25BbhCNfEGGJZnxvCDQCd6JkbvxW6h/1/*)"),
        bitcoin::Network::Testnet,
        MemoryDatabase::default(),
    )?;

    let psbt = "...";
    let psbt = deserialize(&base64::decode(psbt).unwrap())?;

    let (signed_psbt, finalized) = wallet.sign(psbt, None)?;

    Ok(())
}
```
