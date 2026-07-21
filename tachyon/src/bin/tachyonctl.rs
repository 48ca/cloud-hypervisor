// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::os::unix::io::IntoRawFd;

use clap::{ArgAction, Parser, Subcommand};
use log::{LevelFilter, debug};
use tachyon::Operation;
use tachyon::rpc::{Client, Message, RpcClient};

#[derive(Parser)]
#[command(author, version, about = "Command line tool for Tachyon VMM", long_about = None)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Sets the level of debugging output
    #[arg(short, action = ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Save the VM state across kexec
    Save {
        /// Path to the Tachyon RPC socket
        #[arg(long)]
        rpc: String,

        /// Path to the output state image file
        #[arg(long)]
        image: String,
    },
    /// Pause the VM
    Pause {
        /// Path to the Tachyon RPC socket
        #[arg(long)]
        rpc: String,
    },
    /// Unpause the VM
    Unpause {
        /// Path to the Tachyon RPC socket
        #[arg(long)]
        rpc: String,
    },
    /// Perform a live update of the Tachyon VMM binary
    Liveupdate {
        /// Path to the current Tachyon RPC socket
        #[arg(long)]
        rpc: String,

        /// Path to the new Tachyon binary
        #[arg(long)]
        tachyon_bin: String,
    },
}

fn handle_liveupdate(rpc: &str, tachyon_bin: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to old Tachyon process at {}...", rpc);
    let old_channel = Client::connect(rpc)?;
    let old_rpc_client = RpcClient::new(old_channel);

    // 1. Pause the system first to ensure stability
    println!("Pausing the system...");
    let pause_msg = Message {
        msg_type: Operation::Pause as u32,
        request_id: 0,
        handle: 1,
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: Vec::new(),
        fds: None,
    };
    let pause_resp = old_rpc_client.call(pause_msg)?;
    if pause_resp.status != 0 {
        return Err(format!("Failed to pause system: {}", pause_resp.status).into());
    }

    // 2. Spawn the new Tachyon process
    let temp_dir = tempfile::tempdir()?;
    let new_socket_path = temp_dir.path().join("tachyon_new.sock");
    let new_socket_str = new_socket_path.to_str().unwrap();

    println!("Spawning new Tachyon process at {}...", tachyon_bin);
    debug!("Using temporary socket path: {}", new_socket_str);
    let mut command = std::process::Command::new(tachyon_bin);
    command.arg("--socket").arg(new_socket_str);

    // Propagate verbosity
    if let Ok(cli) = Cli::try_parse()
        && cli.verbose > 0
    {
        command.arg(format!("-{}", "v".repeat(cli.verbose as usize)));
    }

    let _new_process = command.spawn()?;

    // Wait a bit for the new process to start listening
    std::thread::sleep(std::time::Duration::from_millis(500));

    println!("Connecting to new Tachyon process at {}...", new_socket_str);
    let new_channel = Client::connect(new_socket_str)?;
    let new_rpc_client = RpcClient::new(new_channel);

    // 3. Send LiveUpdateSave to the old process
    println!("Requesting state from old process (LiveUpdateSave)...");
    let save_msg = Message {
        msg_type: Operation::LiveUpdateSave as u32,
        request_id: 0,
        handle: 1,
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: Vec::new(),
        fds: None,
    };
    let save_resp = old_rpc_client.call(save_msg)?;
    if save_resp.status != 0 {
        return Err(format!("LiveUpdateSave failed: {}", save_resp.status).into());
    }

    // 4. Send LiveUpdateRestore to the new process
    debug!("Starting restore operation on new process (LiveUpdateRestore)...");
    let restore_msg = Message {
        msg_type: Operation::LiveUpdateRestore as u32,
        request_id: 0,
        handle: 1,
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: save_resp.body,
        fds: save_resp.fds,
    };
    let restore_resp = new_rpc_client.call(restore_msg)?;
    if restore_resp.status != 0 {
        return Err(format!("LiveUpdateRestore failed: {}", restore_resp.status).into());
    }
    debug!("Restore operation completed successfully.");

    // 5. Unpause the new process
    println!("Unpausing the new process...");
    let unpause_msg = Message {
        msg_type: Operation::Unpause as u32,
        request_id: 0,
        handle: 1,
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: Vec::new(),
        fds: None,
    };
    let unpause_resp = new_rpc_client.call(unpause_msg)?;
    if unpause_resp.status != 0 {
        return Err(format!("Failed to unpause new system: {}", unpause_resp.status).into());
    }

    println!("Live update successful!");

    Ok(())
}

fn handle_save(rpc: &str, image: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Tachyon RPC at {}...", rpc);
    let channel = Client::connect(rpc)?;
    let rpc_client = RpcClient::new(channel);

    println!("Creating image file at {}...", image);
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(image)?;
    let fd = file.into_raw_fd();

    let msg = Message {
        msg_type: Operation::Save as u32,
        request_id: 0, // Assigned by RpcClient
        handle: 1,     // KvmDevice handle, conceptually system-wide
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: Vec::new(),
        fds: Some(vec![fd]),
    };

    println!("Sending Save request...");
    let resp = rpc_client.call(msg)?;

    // Even if the request is sent, the FD was sent, and we should ideally close it in our process.
    // Since into_raw_fd() consumes the file, we can optionally close it, or let the OS clean it up.
    unsafe {
        libc::close(fd);
    }

    if resp.status == 0 {
        println!("Save successful!");
    } else {
        eprintln!(
            "Save failed with error code: {} ({})",
            resp.status,
            std::io::Error::from_raw_os_error(resp.status as i32)
        );
        std::process::exit(1);
    }

    Ok(())
}

fn handle_pause_unpause(rpc: &str, pause: bool) -> Result<(), Box<dyn std::error::Error>> {
    let op_name = if pause { "Pause" } else { "Unpause" };
    let op = if pause {
        Operation::Pause
    } else {
        Operation::Unpause
    };

    println!("Connecting to Tachyon RPC at {}...", rpc);
    let channel = Client::connect(rpc)?;
    let rpc_client = RpcClient::new(channel);

    let msg = Message {
        msg_type: op as u32,
        request_id: 0,
        handle: 1,
        status: 0,
        arg: 0,
        cmd: 0,
        resp_size: 0,
        body: Vec::new(),
        fds: None,
    };

    println!("Sending {} request...", op_name);
    let resp = rpc_client.call(msg)?;

    if resp.status == 0 {
        println!("{} successful!", op_name);
    } else {
        eprintln!(
            "{} failed with error code: {} ({})",
            op_name,
            resp.status,
            std::io::Error::from_raw_os_error(resp.status as i32)
        );
        std::process::exit(1);
    }

    Ok(())
}

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log_level))
        .expect("Failed to initialize logger");

    match &cli.command {
        Commands::Save { rpc, image } => handle_save(rpc, image),
        Commands::Pause { rpc } => handle_pause_unpause(rpc, true),
        Commands::Unpause { rpc } => handle_pause_unpause(rpc, false),
        Commands::Liveupdate { rpc, tachyon_bin } => handle_liveupdate(rpc, tachyon_bin),
    }
}
