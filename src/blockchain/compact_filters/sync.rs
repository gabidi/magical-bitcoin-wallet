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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hash_types::{BlockHash, FilterHash};
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::GetHeadersMessage;
use bitcoin::util::bip158::BlockFilter;

use super::peer::*;
use super::store::*;
use super::CompactFiltersError;
use crate::error::Error;

pub(crate) const BURIED_CONFIRMATIONS: usize = 100;

pub struct CFSync {
    headers_store: Arc<ChainStore<Full>>,
    cf_store: Arc<CFStore>,
    skip_blocks: usize,
    bundles: Mutex<VecDeque<(BundleStatus, FilterHash, usize)>>,
}

impl CFSync {
    pub fn new(
        headers_store: Arc<ChainStore<Full>>,
        skip_blocks: usize,
        filter_type: u8,
    ) -> Result<Self, CompactFiltersError> {
        let cf_store = Arc::new(CFStore::new(&headers_store, filter_type)?);

        Ok(CFSync {
            headers_store,
            cf_store,
            skip_blocks,
            bundles: Mutex::new(VecDeque::new()),
        })
    }

    pub fn pruned_bundles(&self) -> Result<usize, CompactFiltersError> {
        Ok(self
            .cf_store
            .get_bundles()?
            .into_iter()
            .skip(self.skip_blocks / 1000)
            .fold(0, |acc, (status, _)| match status {
                BundleStatus::Pruned => acc + 1,
                _ => acc,
            }))
    }

    pub fn prepare_sync(&self, peer: Arc<Peer>) -> Result<(), CompactFiltersError> {
        let mut bundles_lock = self.bundles.lock().unwrap();

        let resp = peer.get_cf_checkpt(
            self.cf_store.get_filter_type(),
            self.headers_store.get_tip_hash()?.unwrap(),
        )?;
        self.cf_store.replace_checkpoints(resp.filter_headers)?;

        bundles_lock.clear();
        for (index, (status, checkpoint)) in self.cf_store.get_bundles()?.into_iter().enumerate() {
            bundles_lock.push_back((status, checkpoint, index));
        }

        Ok(())
    }

    pub fn capture_thread_for_sync<F, Q>(
        &self,
        peer: Arc<Peer>,
        process: F,
        completed_bundle: Q,
    ) -> Result<(), CompactFiltersError>
    where
        F: Fn(&BlockHash, &BlockFilter) -> Result<bool, CompactFiltersError>,
        Q: Fn(usize) -> Result<(), Error>,
    {
        let current_height = self.headers_store.get_height()?; // TODO: we should update it in case headers_store is also updated

        loop {
            let (mut status, checkpoint, index) = match self.bundles.lock().unwrap().pop_front() {
                None => break,
                Some(x) => x,
            };

            log::debug!(
                "Processing bundle #{} - height {} to {}",
                index,
                index * 1000 + 1,
                (index + 1) * 1000
            );

            let process_received_filters =
                |expected_filters| -> Result<BTreeMap<usize, Vec<u8>>, CompactFiltersError> {
                    let mut filters_map = BTreeMap::new();
                    for _ in 0..expected_filters {
                        let filter = peer.pop_cf_filter_resp()?;
                        if filter.filter_type != self.cf_store.get_filter_type() {
                            return Err(CompactFiltersError::InvalidResponse);
                        }

                        match self.headers_store.get_height_for(&filter.block_hash)? {
                            Some(height) => filters_map.insert(height, filter.filter),
                            None => return Err(CompactFiltersError::InvalidFilter),
                        };
                    }

                    Ok(filters_map)
                };

            let start_height = index * 1000 + 1;
            let mut already_processed = 0;

            if start_height < self.skip_blocks {
                status = self.cf_store.prune_filters(index, checkpoint)?;
            }

            let stop_height = std::cmp::min(current_height, start_height + 999);
            let stop_hash = self.headers_store.get_block_hash(stop_height)?.unwrap();

            if let BundleStatus::Init = status {
                log::trace!("status: Init");

                let resp = peer.get_cf_headers(0x00, start_height as u32, stop_hash)?;

                assert!(resp.previous_filter == checkpoint);
                status =
                    self.cf_store
                        .advance_to_cf_headers(index, checkpoint, resp.filter_hashes)?;
            }
            if let BundleStatus::Tip { cf_filters } = status {
                log::trace!("status: Tip (beginning) ");

                already_processed = cf_filters.len();
                let headers_resp = peer.get_cf_headers(0x00, start_height as u32, stop_hash)?;

                let cf_headers = match self.cf_store.advance_to_cf_headers(
                    index,
                    checkpoint,
                    headers_resp.filter_hashes,
                )? {
                    BundleStatus::CFHeaders { cf_headers } => cf_headers,
                    _ => return Err(CompactFiltersError::InvalidResponse),
                };

                peer.get_cf_filters(
                    self.cf_store.get_filter_type(),
                    (start_height + cf_filters.len()) as u32,
                    stop_hash,
                )?;
                let expected_filters = stop_height - start_height + 1 - cf_filters.len();
                let filters_map = process_received_filters(expected_filters)?;
                let filters = cf_filters
                    .into_iter()
                    .enumerate()
                    .chain(filters_map.into_iter())
                    .collect();
                status = self
                    .cf_store
                    .advance_to_cf_filters(index, checkpoint, cf_headers, filters)?;
            }
            if let BundleStatus::CFHeaders { cf_headers } = status {
                log::trace!("status: CFHeaders");

                peer.get_cf_filters(
                    self.cf_store.get_filter_type(),
                    start_height as u32,
                    stop_hash,
                )?;
                let expected_filters = stop_height - start_height + 1;
                let filters_map = process_received_filters(expected_filters)?;
                status = self.cf_store.advance_to_cf_filters(
                    index,
                    checkpoint,
                    cf_headers,
                    filters_map.into_iter().collect(),
                )?;
            }
            if let BundleStatus::CFilters { cf_filters } = status {
                log::trace!("status: CFilters");

                let last_sync_buried_height = (start_height + already_processed)
                    .checked_sub(BURIED_CONFIRMATIONS)
                    .unwrap_or(0);

                for (filter_index, filter) in cf_filters.iter().enumerate() {
                    let height = filter_index + start_height;

                    // do not download blocks that were already "buried" since the last sync
                    if height < last_sync_buried_height {
                        continue;
                    }

                    let block_hash = self.headers_store.get_block_hash(height)?.unwrap();

                    // TODO: also download random blocks?
                    if process(&block_hash, &BlockFilter::new(&filter))? {
                        log::debug!("Downloading block {}", block_hash);

                        let block = peer
                            .get_block(block_hash)?
                            .ok_or(CompactFiltersError::MissingBlock)?;
                        self.headers_store.save_full_block(&block, height)?;
                    }
                }

                status = BundleStatus::Processed { cf_filters };
            }
            if let BundleStatus::Processed { cf_filters } = status {
                log::trace!("status: Processed");

                if current_height - stop_height > 1000 {
                    status = self.cf_store.prune_filters(index, checkpoint)?;
                } else {
                    status = self.cf_store.mark_as_tip(index, cf_filters, checkpoint)?;
                }

                completed_bundle(index)?;
            }
            if let BundleStatus::Pruned = status {
                log::trace!("status: Pruned");
            }
            if let BundleStatus::Tip { .. } = status {
                log::trace!("status: Tip");
            }
        }

        Ok(())
    }
}

pub fn sync_headers<F>(
    peer: Arc<Peer>,
    store: Arc<ChainStore<Full>>,
    sync_fn: F,
) -> Result<Option<ChainStore<Snapshot>>, CompactFiltersError>
where
    F: Fn(usize) -> Result<(), Error>,
{
    let locators = store.get_locators()?;
    let locators_vec = locators.iter().map(|(hash, _)| hash).cloned().collect();
    let locators_map: HashMap<_, _> = locators.into_iter().collect();

    peer.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
        locators_vec,
        Default::default(),
    )))?;
    let (mut snapshot, mut last_hash) = if let NetworkMessage::Headers(headers) = peer
        .recv("headers", Some(Duration::from_secs(TIMEOUT_SECS)))?
        .ok_or(CompactFiltersError::Timeout)?
    {
        if headers.is_empty() {
            return Ok(None);
        }

        match locators_map.get(&headers[0].prev_blockhash) {
            None => return Err(CompactFiltersError::InvalidHeaders),
            Some(from) => (
                store.start_snapshot(*from)?,
                headers[0].prev_blockhash.clone(),
            ),
        }
    } else {
        return Err(CompactFiltersError::InvalidResponse);
    };

    let mut sync_height = store.get_height()?;
    while sync_height < peer.get_version().start_height as usize {
        peer.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![last_hash],
            Default::default(),
        )))?;
        if let NetworkMessage::Headers(headers) = peer
            .recv("headers", Some(Duration::from_secs(TIMEOUT_SECS)))?
            .ok_or(CompactFiltersError::Timeout)?
        {
            let batch_len = headers.len();
            last_hash = snapshot.apply(sync_height, headers)?;

            sync_height += batch_len;
            sync_fn(sync_height)?;
        } else {
            return Err(CompactFiltersError::InvalidResponse);
        }
    }

    Ok(Some(snapshot))
}
