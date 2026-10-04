use std::{
    collections::VecDeque,
    io::{self, BufWriter, Read, Write},
    time::Instant,
};

use super::{
    MAX_QUALIFIER_GAP_BYTES, MAX_QUOTED_IDENTIFIER_BYTES, MysqlSqlRewriteError, STREAM_BUFFER_BYTES,
};

pub(super) struct BoundedInput<R> {
    pub(super) reader: R,
    pub(super) buffer: Box<[u8]>,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) lookahead: VecDeque<u8>,
    pub(super) bytes_read: u64,
    pub(super) max_bytes: u64,
    pub(super) deadline: Instant,
}

impl<R: Read> BoundedInput<R> {
    pub(super) fn new(reader: R, max_bytes: u64, deadline: Instant) -> Self {
        Self {
            reader,
            buffer: vec![0; STREAM_BUFFER_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
            lookahead: VecDeque::with_capacity(4),
            bytes_read: 0,
            max_bytes,
            deadline,
        }
    }

    pub(super) fn available(&mut self) -> Result<&[u8], MysqlSqlRewriteError> {
        if !self.lookahead.is_empty() {
            return Ok(self.lookahead.as_slices().0);
        }
        self.fill_buffer()?;
        Ok(&self.buffer[self.start..self.end])
    }

    pub(super) fn consume(&mut self, length: usize) {
        if !self.lookahead.is_empty() {
            debug_assert!(length <= self.lookahead.as_slices().0.len());
            for _ in 0..length {
                let _ = self.lookahead.pop_front();
            }
        } else {
            debug_assert!(length <= self.end - self.start);
            self.start += length;
        }
    }

    pub(super) fn next_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        if let Some(byte) = self.lookahead.pop_front() {
            return Ok(Some(byte));
        }
        self.next_buffer_byte()
    }

    pub(super) fn next_buffer_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        self.fill_buffer()?;
        if self.start == self.end {
            return Ok(None);
        }
        let byte = self.buffer[self.start];
        self.start += 1;
        Ok(Some(byte))
    }

    pub(super) fn peek_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        self.peek_nth_byte(0)
    }

    pub(super) fn peek_nth_byte(
        &mut self,
        index: usize,
    ) -> Result<Option<u8>, MysqlSqlRewriteError> {
        while self.lookahead.len() <= index {
            let Some(byte) = self.next_buffer_byte()? else {
                return Ok(None);
            };
            self.lookahead.push_back(byte);
        }
        Ok(self.lookahead.get(index).copied())
    }

    pub(super) fn fill_buffer(&mut self) -> Result<(), MysqlSqlRewriteError> {
        if self.start < self.end {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            return Err(MysqlSqlRewriteError::Timeout);
        }
        self.start = 0;
        self.end = 0;

        let remaining = self.max_bytes.saturating_sub(self.bytes_read);
        let requested = if remaining >= self.buffer.len() as u64 {
            self.buffer.len()
        } else {
            usize::try_from(remaining)
                .unwrap_or(self.buffer.len() - 1)
                .saturating_add(1)
                .min(self.buffer.len())
        };
        let read = loop {
            match self.reader.read(&mut self.buffer[..requested]) {
                Ok(read) => break read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(MysqlSqlRewriteError::Io(error)),
            }
        };
        if u64::try_from(read).unwrap_or(u64::MAX) > remaining {
            return Err(MysqlSqlRewriteError::InputLimit {
                limit: self.max_bytes,
            });
        }
        self.bytes_read += u64::try_from(read).unwrap_or(u64::MAX);
        self.end = read;
        Ok(())
    }
}

pub(super) struct BoundedOutput<W: Write> {
    pub(super) writer: BufWriter<W>,
    pub(super) bytes_written: u64,
    pub(super) max_bytes: u64,
}

impl<W: Write> BoundedOutput<W> {
    pub(super) fn new(writer: W, max_bytes: u64) -> Self {
        Self {
            writer: BufWriter::with_capacity(STREAM_BUFFER_BYTES, writer),
            bytes_written: 0,
            max_bytes,
        }
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), MysqlSqlRewriteError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let new_length =
            self.bytes_written
                .checked_add(length)
                .ok_or(MysqlSqlRewriteError::OutputLimit {
                    limit: self.max_bytes,
                })?;
        if new_length > self.max_bytes {
            return Err(MysqlSqlRewriteError::OutputLimit {
                limit: self.max_bytes,
            });
        }
        self.writer.write_all(bytes)?;
        self.bytes_written = new_length;
        Ok(())
    }

    pub(super) fn write_byte(&mut self, byte: u8) -> Result<(), MysqlSqlRewriteError> {
        self.write_bytes(&[byte])
    }

    pub(super) fn flush(&mut self) -> Result<(), MysqlSqlRewriteError> {
        self.writer.flush()?;
        Ok(())
    }
}

pub(super) fn push_gap_byte(gap: &mut Vec<u8>, byte: u8) -> Result<(), MysqlSqlRewriteError> {
    if gap.len() >= MAX_QUALIFIER_GAP_BYTES {
        return Err(MysqlSqlRewriteError::Malformed(
            "source qualifier separators exceed the token limit",
        ));
    }
    gap.push(byte);
    Ok(())
}

pub(super) fn push_token_byte(token: &mut Vec<u8>, byte: u8) -> Result<(), MysqlSqlRewriteError> {
    if token.len() >= MAX_QUOTED_IDENTIFIER_BYTES {
        return Err(MysqlSqlRewriteError::Malformed(
            "quoted identifier exceeds the token limit",
        ));
    }
    token.push(byte);
    Ok(())
}
