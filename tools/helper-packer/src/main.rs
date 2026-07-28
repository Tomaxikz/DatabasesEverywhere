use std::{
    env,
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    process::ExitCode,
};

const ZSTD_LEVEL: i32 = 19;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("helper packer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let source = PathBuf::from(arguments.next().ok_or("missing source executable")?);
    let destination = PathBuf::from(arguments.next().ok_or("missing destination payload")?);
    if arguments.next().is_some() {
        return Err("expected exactly a source executable and destination payload".into());
    }

    let mut source_reader = BufReader::new(File::open(&source)?);
    let destination_file = File::create(&destination)?;
    let mut destination_writer = BufWriter::new(destination_file);
    zstd::stream::copy_encode(&mut source_reader, &mut destination_writer, ZSTD_LEVEL)?;
    destination_writer.flush()?;
    destination_writer.get_ref().sync_all()?;
    drop(destination_writer);

    let unpacked = zstd::decode_all(BufReader::new(File::open(&destination)?))?;
    if unpacked != fs::read(&source)? {
        return Err("compressed helper did not round-trip to the source executable".into());
    }
    Ok(())
}
