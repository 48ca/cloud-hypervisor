// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use clap::{ArgAction, Parser};
use log::{LevelFilter, error, warn};
use tachyon::System;
use tachyon::rpc::Server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the RPC socket
    #[arg(short, long, default_value = "/tmp/tachyon.sock")]
    socket: String,

    /// Sets the level of debugging output
    #[arg(short, action = ArgAction::Count)]
    verbose: u8,

    /// Path to the state image file for restoration
    #[arg(short, long)]
    restore: Option<String>,

    /// Path to VM configuration proto.
    #[arg(long)]
    vm_config: Option<String>,
}

struct Logger {
    output: Mutex<Box<dyn std::io::Write + Send>>,
    start: std::time::Instant,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);
        let current_thread = std::thread::current();
        let thread_name = current_thread
            .name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("{:?}", current_thread.id()));

        if record.file().is_some() && record.line().is_some() {
            let _ = writeln!(
                *self.output.lock().unwrap(),
                "tachyon: {:.6?}: <{}> {}:{}:{} -- {}",
                duration,
                thread_name,
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            );
        } else {
            let _ = writeln!(
                *self.output.lock().unwrap(),
                "tachyon: {:.6?}: <{}> {}:{} -- {}",
                duration,
                thread_name,
                record.level(),
                record.target(),
                record.args()
            );
        }
    }
    fn flush(&self) {}
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let logger = Logger {
        output: Mutex::new(Box::new(std::io::stderr())),
        start: std::time::Instant::now(),
    };

    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(log_level))
        .expect("Failed to initialize logger");

    warn!(
        "Starting tachyon VMM version 2.0-RPC-HANDOVER on {}",
        args.socket
    );

    let server = Server::new(&args.socket)?;

    let system = if let Some(image_path) = &args.restore {
        warn!("Waiting for an initial client connection to provide state FD...");
        let channel = server.accept()?;
        warn!("Client connected, restoring state...");
        let channel = std::sync::Arc::new(channel);
        let mut file = std::fs::File::open(image_path)?;
        let system = System::new_empty();
        System::restore(&system, &mut file, channel.clone())?;
        system
    } else {
        System::new()?
    };

    // Register the initial server as a handle
    use std::os::unix::io::AsRawFd;

    use tachyon::{Handle, RpcChannelOps, RpcServerOps, luo_preserve};
    let server_handle = Handle::new(
        None,
        None,
        std::sync::Arc::new(RpcServerOps {
            socket_path: args.socket.clone(),
            luo_id: luo_preserve(server.as_raw_fd()),
        }),
    );
    system.add_handle(server_handle);

    warn!("Tachyon system ready. Waiting for client connections...");

    loop {
        match server.accept() {
            Ok(channel) => {
                warn!("New client connected!");
                let channel_fd = channel.as_raw_fd();
                let channel_luo_id = luo_preserve(channel_fd);
                let channel_handle = Handle::new(
                    None,
                    None,
                    std::sync::Arc::new(RpcChannelOps {
                        luo_id: channel_luo_id,
                        channel: Mutex::new(None),
                    }),
                );
                let handle_id = channel_handle.id();
                system.add_handle(channel_handle);

                let channel = std::sync::Arc::new(channel);
                system.handle_channel(channel, Some(handle_id));
            }
            Err(e) => {
                error!("Failed to accept connection: {:?}", e);
            }
        }
    }
}
