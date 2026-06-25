//! Taint tracking for Validator (only enabled during REPLAY in validator thread)

use crate::input::{MultiStream, StreamKey};

pub struct TaintTracker {
    mmio_reads: Vec<(u64, StreamKey, usize, usize, u64)>,
    current_icount: u64,
}

impl TaintTracker {
    pub fn new() -> Self {
        Self {
            mmio_reads: Vec::new(),
            current_icount: 0,
        }
    }

    pub fn record_mmio_read(
        &mut self,
        mmio_addr: u64,
        stream_key: StreamKey,
        offset: usize,
        size: usize,
        icount: u64,
    ) {
        self.mmio_reads
            .push((mmio_addr, stream_key, offset, size, icount));
    }

    pub fn update_icount(&mut self, icount: u64) {
        self.current_icount = icount;
    }

    pub fn get_all_read_bytes(&self) -> Vec<(StreamKey, usize, usize)> {
        let mut result = Vec::new();
        let mut current: Option<(StreamKey, usize, usize)> = None;

        let mut sorted_reads = self.mmio_reads.clone();
        sorted_reads.sort_by_key(|(_, sk, off, _, _)| (*sk, *off));

        for (_, sk, off, sz, _) in sorted_reads {
            if let Some((c_sk, c_off, c_sz)) = current {
                if c_sk == sk && c_off + c_sz == off {
                    current = Some((c_sk, c_off, c_sz + sz));
                } else {
                    result.push((c_sk, c_off, c_sz));
                    current = Some((sk, off, sz));
                }
            } else {
                current = Some((sk, off, sz));
            }
        }

        if let Some(range) = current {
            result.push(range);
        }

        result
    }

    pub fn get_recent_read_bytes(&self, lookback_blocks: u64) -> Vec<(StreamKey, usize, usize)> {
        let threshold = self.current_icount.saturating_sub(lookback_blocks * 10);
        self.mmio_reads
            .iter()
            .filter(|(_, _, _, _, icount)| *icount >= threshold)
            .map(|(_, sk, off, sz, _)| (*sk, *off, *sz))
            .collect()
    }

    pub fn get_mmio_access_log(&self) -> Vec<(u64, StreamKey, usize, usize)> {
        self.mmio_reads
            .iter()
            .map(|(mmio_addr, sk, off, sz, _)| (*mmio_addr, *sk, *off, *sz))
            .collect()
    }
}

#[allow(dead_code)]
pub struct TaintTrackingMultiStream {
    inner: MultiStream,
    tracker: Option<TaintTracker>,
}

impl TaintTrackingMultiStream {
    pub fn new(inner: MultiStream, enable_taint: bool) -> Self {
        Self {
            inner,
            tracker: if enable_taint {
                Some(TaintTracker::new())
            } else {
                None
            },
        }
    }

    pub fn get_tracker(&self) -> Option<&TaintTracker> {
        self.tracker.as_ref()
    }

    pub fn get_tracker_mut(&mut self) -> Option<&mut TaintTracker> {
        self.tracker.as_mut()
    }

    pub fn into_inner(self) -> MultiStream {
        self.inner
    }

    pub fn inner_mut(&mut self) -> &mut MultiStream {
        &mut self.inner
    }
}

