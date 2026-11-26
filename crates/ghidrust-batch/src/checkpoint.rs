//! Append-only checkpoint file for resumable batch decompilation.
//!
//! Format: versioned binary fingerprint header followed by completed hex addresses.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Manages an append-only checkpoint file.
pub struct Checkpoint {
    path: PathBuf,
    fingerprint: String,
    completed: HashSet<u64>,
    writer: Option<BufWriter<File>>,
}

impl Checkpoint {
    /// Create a new checkpoint (no file yet).
    pub fn new(path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            fingerprint: fingerprint.into(),
            completed: HashSet::new(),
            writer: None,
        }
    }

    /// Create a no-op checkpoint that doesn't write to disk.
    pub fn none() -> Self {
        Self {
            path: PathBuf::new(),
            fingerprint: String::new(),
            completed: HashSet::new(),
            writer: None,
        }
    }

    /// Load existing checkpoint from disk. Returns the set of completed addresses.
    pub fn load(&mut self) -> io::Result<usize> {
        if !self.path.exists() {
            return Ok(0);
        }
        repair_checkpoint_tail(&self.path)?;
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        self.completed.clear();
        let mut lines = reader.lines();
        let header = lines.next().transpose()?.unwrap_or_default();
        let expected = format!("# ghidrust-checkpoint-v1 {}", self.fingerprint);
        if header != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "checkpoint fingerprint mismatch",
            ));
        }
        for line in lines {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(addr) = u64::from_str_radix(trimmed.trim_start_matches("0x"), 16) {
                self.completed.insert(addr);
            }
        }
        Ok(self.completed.len())
    }

    /// Open the checkpoint file for appending.
    pub fn open_for_append(&mut self) -> io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let existed = self.path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = Some(BufWriter::new(file));
        if !existed {
            if let Some(w) = &mut self.writer {
                writeln!(w, "# ghidrust-checkpoint-v1 {}", self.fingerprint)?;
                w.flush()?;
            }
        }
        Ok(())
    }

    /// Start a new run, deliberately discarding only this checkpoint's prior state.
    pub fn reset(&mut self) -> io::Result<()> {
        self.completed.clear();
        self.writer = None;
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(&self.path)?;
        writeln!(file, "# ghidrust-checkpoint-v1 {}", self.fingerprint)?;
        file.flush()?;
        self.writer = Some(BufWriter::new(file));
        Ok(())
    }

    /// Record a completed function address.
    pub fn record(&mut self, addr: u64) -> io::Result<()> {
        self.completed.insert(addr);
        if let Some(ref mut w) = self.writer {
            writeln!(w, "{addr:016x}")?;
        }
        Ok(())
    }

    /// Flush completed addresses after the corresponding output records are flushed.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = &mut self.writer {
            writer.flush()?;
        }
        Ok(())
    }

    /// Mark an address recovered from a durable JSONL export without appending it again.
    pub fn mark_completed(&mut self, addr: u64) {
        self.completed.insert(addr);
    }

    /// Check if an address was already completed.
    pub fn is_completed(&self, addr: u64) -> bool {
        self.completed.contains(&addr)
    }

    /// Number of completed functions.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Path to the checkpoint file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn repair_checkpoint_tail(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    if byte[0] == b'\n' {
        return Ok(());
    }
    let mut pos = len;
    while pos > 0 {
        pos -= 1;
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            file.set_len(pos + 1)?;
            return Ok(());
        }
    }
    file.set_len(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.txt");

        let mut ckpt = Checkpoint::new(&path, "synthetic-sha256");
        ckpt.open_for_append().unwrap();
        ckpt.record(0x1000).unwrap();
        ckpt.record(0x2000).unwrap();
        assert!(ckpt.is_completed(0x1000));
        assert!(!ckpt.is_completed(0x3000));
        drop(ckpt);

        let mut ckpt2 = Checkpoint::new(&path, "synthetic-sha256");
        let n = ckpt2.load().unwrap();
        assert_eq!(n, 2);
        assert!(ckpt2.is_completed(0x1000));
        assert!(ckpt2.is_completed(0x2000));
    }

    #[test]
    fn rejects_checkpoint_for_different_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.txt");
        let mut ckpt = Checkpoint::new(&path, "hash-a");
        ckpt.open_for_append().unwrap();
        ckpt.record(0x1000).unwrap();
        drop(ckpt);
        let mut wrong_binary = Checkpoint::new(&path, "hash-b");
        assert_eq!(
            wrong_binary.load().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn reset_starts_clean_checkpoint_for_explicit_fresh_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.txt");
        let mut ckpt = Checkpoint::new(&path, "same-binary");
        ckpt.open_for_append().unwrap();
        ckpt.record(0x1000).unwrap();
        ckpt.reset().unwrap();
        ckpt.record(0x2000).unwrap();
        drop(ckpt);
        let mut check = Checkpoint::new(&path, "same-binary");
        assert_eq!(check.load().unwrap(), 1);
        assert!(!check.is_completed(0x1000));
        assert!(check.is_completed(0x2000));
    }
}
