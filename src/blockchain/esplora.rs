// Magical Bitcoin Library
// Written in 2020 by
//     Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020 Magical Bitcoin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Esplora
//!
//! This module defines a [`Blockchain`] struct that can query an Esplora backend
//! populate the wallet's [database](crate::database::Database) by
//!
//! ## Example
//!
//! ```no_run
//! # use magical::blockchain::esplora::EsploraBlockchain;
//! let blockchain = EsploraBlockchain::new("https://blockstream.info/testnet/api");
//! # Ok::<(), magical::Error>(())
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use futures::stream::{self, StreamExt, TryStreamExt};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use serde::Deserialize;

use reqwest::{Client, StatusCode};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Script, Transaction, Txid};

use self::utils::{ELSGetHistoryRes, ELSListUnspentRes, ElectrumLikeSync};
use super::*;
use crate::database::BatchDatabase;
use crate::error::Error;
use crate::FeeRate;

#[derive(Debug)]
struct UrlClient {
    url: String,
    // We use the async client instead of the blocking one because it automatically uses `fetch`
    // when the target platform is wasm32.
    client: Client,
}

/// Structure that implements the logic to sync with Esplora
///
/// ## Example
/// See the [`blockchain::esplora`](crate::blockchain::esplora) module for a usage example.
#[derive(Debug)]
pub struct EsploraBlockchain(UrlClient);

impl std::convert::From<UrlClient> for EsploraBlockchain {
    fn from(url_client: UrlClient) -> Self {
        EsploraBlockchain(url_client)
    }
}

impl EsploraBlockchain {
    /// Create a new instance of the client from a base URL
    pub fn new(base_url: &str) -> Self {
        EsploraBlockchain(UrlClient {
            url: base_url.to_string(),
            client: Client::new(),
        })
    }
}

#[maybe_async]
impl Blockchain for EsploraBlockchain {
    fn get_capabilities(&self) -> HashSet<Capability> {
        vec![
            Capability::FullHistory,
            Capability::GetAnyTx,
            Capability::AccurateFees,
        ]
        .into_iter()
        .collect()
    }

    fn setup<D: BatchDatabase, P: Progress>(
        &self,
        stop_gap: Option<usize>,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self
            .0
            .electrum_like_setup(stop_gap, database, progress_update))
    }

    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        Ok(await_or_block!(self.0._get_tx(txid))?)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        Ok(await_or_block!(self.0._broadcast(tx))?)
    }

    fn get_height(&self) -> Result<u32, Error> {
        Ok(await_or_block!(self.0._get_height())?)
    }

    fn estimate_fee(&self, target: usize) -> Result<FeeRate, Error> {
        let estimates = await_or_block!(self.0._get_fee_estimates())?;

        let fee_val = estimates
            .into_iter()
            .map(|(k, v)| Ok::<_, std::num::ParseIntError>((k.parse::<usize>()?, v)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Generic(e.to_string()))?
            .into_iter()
            .take_while(|(k, _)| k <= &target)
            .map(|(_, v)| v)
            .last()
            .unwrap_or(1.0);

        Ok(FeeRate::from_sat_per_vb(fee_val as f32))
    }
}

impl UrlClient {
    fn script_to_scripthash(script: &Script) -> String {
        sha256::Hash::hash(script.as_bytes()).into_inner().to_hex()
    }

    async fn _get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, EsploraError> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/raw", self.url, txid))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        Ok(Some(deserialize(&resp.error_for_status()?.bytes().await?)?))
    }

    async fn _broadcast(&self, transaction: &Transaction) -> Result<(), EsploraError> {
        self.client
            .post(&format!("{}/tx", self.url))
            .body(serialize(transaction).to_hex())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn _get_height(&self) -> Result<u32, EsploraError> {
        let req = self
            .client
            .get(&format!("{}/blocks/tip/height", self.url))
            .send()
            .await?;

        Ok(req.error_for_status()?.text().await?.parse()?)
    }

    async fn _script_get_history(
        &self,
        script: &Script,
    ) -> Result<Vec<ELSGetHistoryRes>, EsploraError> {
        let mut result = Vec::new();
        let scripthash = Self::script_to_scripthash(script);

        // Add the unconfirmed transactions first
        result.extend(
            self.client
                .get(&format!(
                    "{}/scripthash/{}/txs/mempool",
                    self.url, scripthash
                ))
                .send()
                .await?
                .error_for_status()?
                .json::<Vec<EsploraGetHistory>>()
                .await?
                .into_iter()
                .map(|x| ELSGetHistoryRes {
                    tx_hash: x.txid,
                    height: x.status.block_height.unwrap_or(0) as i32,
                }),
        );

        debug!(
            "Found {} mempool txs for {} - {:?}",
            result.len(),
            scripthash,
            script
        );

        // Then go through all the pages of confirmed transactions
        let mut last_txid = String::new();
        loop {
            let response = self
                .client
                .get(&format!(
                    "{}/scripthash/{}/txs/chain/{}",
                    self.url, scripthash, last_txid
                ))
                .send()
                .await?
                .error_for_status()?
                .json::<Vec<EsploraGetHistory>>()
                .await?;
            let len = response.len();
            if let Some(elem) = response.last() {
                last_txid = elem.txid.to_hex();
            }

            debug!("... adding {} confirmed transactions", len);

            result.extend(response.into_iter().map(|x| ELSGetHistoryRes {
                tx_hash: x.txid,
                height: x.status.block_height.unwrap_or(0) as i32,
            }));

            if len < 25 {
                break;
            }
        }

        Ok(result)
    }

    async fn _script_list_unspent(
        &self,
        script: &Script,
    ) -> Result<Vec<ELSListUnspentRes>, EsploraError> {
        Ok(self
            .client
            .get(&format!(
                "{}/scripthash/{}/utxo",
                self.url,
                Self::script_to_scripthash(script)
            ))
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<EsploraListUnspent>>()
            .await?
            .into_iter()
            .map(|x| ELSListUnspentRes {
                tx_hash: x.txid,
                height: x.status.block_height.unwrap_or(0),
                tx_pos: x.vout,
            })
            .collect())
    }

    async fn _get_fee_estimates(&self) -> Result<HashMap<String, f64>, EsploraError> {
        Ok(self
            .client
            .get(&format!("{}/fee-estimates", self.url,))
            .send()
            .await?
            .error_for_status()?
            .json::<HashMap<String, f64>>()
            .await?)
    }
}

#[maybe_async]
impl ElectrumLikeSync for UrlClient {
    fn els_batch_script_get_history<'s, I: IntoIterator<Item = &'s Script>>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ELSGetHistoryRes>>, Error> {
        let future = async {
            Ok(stream::iter(scripts)
                .then(|script| self._script_get_history(&script))
                .try_collect()
                .await?)
        };

        await_or_block!(future)
    }

    fn els_batch_script_list_unspent<'s, I: IntoIterator<Item = &'s Script>>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ELSListUnspentRes>>, Error> {
        let future = async {
            Ok(stream::iter(scripts)
                .then(|script| self._script_list_unspent(&script))
                .try_collect()
                .await?)
        };

        await_or_block!(future)
    }

    fn els_transaction_get(&self, txid: &Txid) -> Result<Transaction, Error> {
        Ok(await_or_block!(self._get_tx(txid))?
            .ok_or_else(|| EsploraError::TransactionNotFound(*txid))?)
    }
}

#[derive(Deserialize)]
struct EsploraGetHistoryStatus {
    block_height: Option<usize>,
}

#[derive(Deserialize)]
struct EsploraGetHistory {
    txid: Txid,
    status: EsploraGetHistoryStatus,
}

#[derive(Deserialize)]
struct EsploraListUnspent {
    txid: Txid,
    vout: usize,
    status: EsploraGetHistoryStatus,
}

/// Errors that can happen during a sync with [`EsploraBlockchain`]
#[derive(Debug)]
pub enum EsploraError {
    /// Error with the HTTP call
    Reqwest(reqwest::Error),
    /// Invalid number returned
    Parsing(std::num::ParseIntError),
    /// Invalid Bitcoin data returned
    BitcoinEncoding(bitcoin::consensus::encode::Error),

    /// Transaction not found
    TransactionNotFound(Txid),
}

impl fmt::Display for EsploraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EsploraError {}

impl From<reqwest::Error> for EsploraError {
    fn from(other: reqwest::Error) -> Self {
        EsploraError::Reqwest(other)
    }
}

impl From<std::num::ParseIntError> for EsploraError {
    fn from(other: std::num::ParseIntError) -> Self {
        EsploraError::Parsing(other)
    }
}

impl From<bitcoin::consensus::encode::Error> for EsploraError {
    fn from(other: bitcoin::consensus::encode::Error) -> Self {
        EsploraError::BitcoinEncoding(other)
    }
}
