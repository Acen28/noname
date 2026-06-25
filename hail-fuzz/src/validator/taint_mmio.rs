//! Taint-tracking MMIO handler wrapper for Validator

use crate::input::MultiStream;
use crate::validator::taint::TaintTracker;
use icicle_vm::cpu::mem::{IoMemory, MemResult};

#[allow(dead_code)]
pub struct TaintTrackingMmioHandler {
    inner: MultiStream,
    tracker: TaintTracker,
}

impl TaintTrackingMmioHandler {
    pub fn new(inner: MultiStream) -> Self {
        Self {
            inner,
            tracker: TaintTracker::new(),
        }
    }

    pub fn get_tracker(&self) -> &TaintTracker {
        &self.tracker
    }

    pub fn get_tracker_mut(&mut self) -> &mut TaintTracker {
        &mut self.tracker
    }

    pub fn into_inner(self) -> MultiStream {
        self.inner
    }
}

impl IoMemory for TaintTrackingMmioHandler {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.inner.read(addr, buf)?;

        let stream_key = self.inner.last_read.unwrap_or(0);
        if let Some(stream) = self.inner.streams.get(&stream_key) {
            let offset = stream.cursor as usize;
            let size = buf.len();
            let icount = 0;
            self.tracker
                .record_mmio_read(addr, stream_key, offset, size, icount);
        }

        Ok(())
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()> {
        self.inner.write(addr, value)
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        self.inner.snapshot()
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        self.inner.restore(snapshot)
    }
}
