use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    BZIP2_MAGIC, DumpArchiveFormat, FORMAT_SNIFF_BYTES, GZIP_MAGIC, HASH_BUFFER_BYTES,
    InspectionError, MAX_SOURCE_BYTES, TAR_MAGIC, TAR_MAGIC_OFFSET, TAR_MIN_HEADER_BYTES,
    ZIP_SIGNATURES,
};

pub(super) fn open_regular_no_follow(path: &Path) -> Result<File, InspectionError> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or(InspectionError::Invalid(
        "uploaded dump path has no parent directory",
    ))?;
    let name = path.file_name().ok_or(InspectionError::Invalid(
        "uploaded dump path has no file name",
    ))?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let descriptor = rustix::fs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(InspectionError::Invalid(
            "uploaded dump must be a real regular file",
        ));
    }
    Ok(file)
}

pub(super) fn sha256_reader(file: &mut File, deadline: Instant) -> Result<String, InspectionError> {
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        ensure_deadline(deadline)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(InspectionError::Limit(
                "uploaded dump exceeds the size limit",
            ))?;
        if total > MAX_SOURCE_BYTES {
            return Err(InspectionError::Limit(
                "uploaded dump exceeds the size limit",
            ));
        }
        hash.update(&buffer[..read]);
    }
    Ok(crate::utils::hex::encode_lower(&hash.finalize()))
}

pub(super) fn detect_archive_format(
    file: &mut File,
    deadline: Instant,
) -> Result<DumpArchiveFormat, InspectionError> {
    ensure_deadline(deadline)?;
    let mut buffer = [0_u8; FORMAT_SNIFF_BYTES];
    let read = read_up_to(file, &mut buffer)?;
    file.seek(SeekFrom::Start(0))?;
    let header = &buffer[..read];
    if header.starts_with(GZIP_MAGIC) {
        let mut decoder = flate2::read::GzDecoder::new(&mut *file);
        let mut inner = [0_u8; FORMAT_SNIFF_BYTES];
        let inner_read = read_up_to(&mut decoder, &mut inner)
            .map_err(|_| InspectionError::Invalid("uploaded gzip stream is malformed"))?;
        return Ok(if is_tar_header(&inner[..inner_read]) {
            DumpArchiveFormat::TarGzip
        } else {
            DumpArchiveFormat::Gzip
        });
    }
    if header.starts_with(BZIP2_MAGIC) {
        return Ok(DumpArchiveFormat::Bzip2);
    }
    if ZIP_SIGNATURES
        .iter()
        .any(|signature| header.starts_with(signature))
    {
        return Ok(DumpArchiveFormat::Zip);
    }
    if is_tar_header(header) {
        return Ok(DumpArchiveFormat::Tar);
    }
    Ok(DumpArchiveFormat::Plain)
}

pub(super) fn is_tar_header(bytes: &[u8]) -> bool {
    bytes.len() >= TAR_MIN_HEADER_BYTES
        && &bytes[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()] == TAR_MAGIC
}

pub(super) fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut total = 0_usize;
    while total < buffer.len() {
        match reader.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(read) => total += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

pub(super) fn ensure_deadline(deadline: Instant) -> Result<(), InspectionError> {
    if Instant::now() >= deadline {
        Err(InspectionError::Limit(
            "dump inspection exceeded its time limit",
        ))
    } else {
        Ok(())
    }
}

pub(super) struct BoundedReader<R> {
    pub(super) inner: R,
    pub(super) read: u64,
    pub(super) limit: u64,
    pub(super) deadline: Instant,
}

impl<R> BoundedReader<R> {
    pub(super) fn new(inner: R, limit: u64, deadline: Instant) -> Self {
        Self {
            inner,
            read: 0,
            limit,
            deadline,
        }
    }

    pub(super) fn next_request_len(&self, buffer_len: usize) -> usize {
        let remaining = self.limit.saturating_sub(self.read);
        if remaining >= buffer_len as u64 {
            return buffer_len;
        }
        usize::try_from(remaining)
            .unwrap_or(buffer_len.saturating_sub(1))
            .saturating_add(1)
            .min(buffer_len)
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "dump inspection exceeded its time limit",
            ));
        }
        let request = self.next_request_len(buffer.len());
        let count = self.inner.read(&mut buffer[..request])?;
        self.read = self.read.saturating_add(count as u64);
        if self.read > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed dump exceeds inspection limit",
            ));
        }
        Ok(count)
    }
}
