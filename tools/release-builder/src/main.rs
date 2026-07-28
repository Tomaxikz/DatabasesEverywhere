use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    path::Path,
    process::{Child, Command, ExitCode, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct ReleaseBuild {
    label: &'static str,
    cargo_subcommand: &'static str,
    target: &'static str,
    artifact: &'static str,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("\nrelease build failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--help") {
        print_help();
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err(format!(
            "unexpected argument {}; run `cargo b --help` for usage",
            arguments[0].to_string_lossy()
        )
        .into());
    }

    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("release-builder must remain under tools/release-builder")?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let build = release_build();
    let needs_zig = build.cargo_subcommand == "zigbuild";
    let zig = if needs_zig {
        require_command(
            &cargo,
            ["zigbuild", "--help"],
            "cargo-zigbuild is required; install it with `cargo install cargo-zigbuild --locked`",
        )?;
        let zig = env::var_os("CARGO_ZIGBUILD_ZIG_PATH")
            .or_else(|| env::var_os("ZIG"))
            .unwrap_or_else(|| OsString::from("zig"));
        require_command(
            &zig,
            ["version"],
            "Zig is required; put `zig` on PATH or set CARGO_ZIGBUILD_ZIG_PATH",
        )?;
        Some(zig)
    } else {
        None
    };

    println!("Building the dbev Linux x86-64 release.");
    println!("The artifact stays in Cargo's standard target/<triple>/release directory.\n");

    let available_jobs = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2);
    println!("Starting: {}", build.label);
    let status = spawn_cargo(&cargo, repository, &build, available_jobs, zig.as_deref())?
        .wait()
        .map_err(|error| format!("could not wait for {}: {error}", build.label))?;
    if !status.success() {
        return Err(format!(
            "{} exited with {}; ensure Rust target `{}` is installed",
            build.label, status, build.target
        )
        .into());
    }

    let artifact = repository.join(build.artifact);
    let size = artifact
        .metadata()
        .map_err(|error| {
            format!(
                "{} completed but {} was not produced: {error}",
                build.label,
                artifact.display()
            )
        })?
        .len();
    println!("Ready: {} ({})", artifact.display(), human_bytes(size));
    println!("\nLinux release binary is ready.");
    Ok(())
}

fn release_build() -> ReleaseBuild {
    #[cfg(target_os = "windows")]
    {
        ReleaseBuild {
            label: "Linux x86-64 server (static musl)",
            cargo_subcommand: "zigbuild",
            target: "x86_64-unknown-linux-musl",
            artifact: "target/x86_64-unknown-linux-musl/release/dbev",
        }
    }

    #[cfg(target_os = "linux")]
    {
        ReleaseBuild {
            label: "Linux x86-64 server (GNU)",
            cargo_subcommand: "build",
            target: "x86_64-unknown-linux-gnu",
            artifact: "target/x86_64-unknown-linux-gnu/release/dbev",
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        ReleaseBuild {
            label: "Linux x86-64 server (static musl)",
            cargo_subcommand: "zigbuild",
            target: "x86_64-unknown-linux-musl",
            artifact: "target/x86_64-unknown-linux-musl/release/dbev",
        }
    }
}

fn spawn_cargo(
    cargo: &OsStr,
    repository: &Path,
    build: &ReleaseBuild,
    jobs: usize,
    zig: Option<&OsStr>,
) -> Result<Child> {
    let mut command = Command::new(cargo);
    command
        .current_dir(repository)
        .args([
            build.cargo_subcommand,
            "--release",
            "--locked",
            "--bin",
            "dbev",
            "--target",
            build.target,
            "--jobs",
        ])
        .arg(jobs.to_string())
        .arg("--target-dir")
        .arg(repository.join("target"));
    if build.cargo_subcommand == "zigbuild"
        && let Some(zig) = zig
    {
        command.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    command
        .spawn()
        .map_err(|error| format!("could not start Cargo for {}: {error}", build.label).into())
}

fn require_command<I, S>(program: &OsStr, arguments: I, error_message: &str) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok_and(|status| status.success()) {
        Ok(())
    } else {
        Err(error_message.into())
    }
}

fn human_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

fn print_help() {
    println!(
        "\
Build the optimized dbev Linux x86-64 binary.

Usage:
  cargo b

The artifact is written to Cargo's standard target/<triple>/release path.
Cross-compiling from a non-Linux host requires cargo-zigbuild, Zig, and the
x86_64-unknown-linux-musl Rust target."
    );
}
