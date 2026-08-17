// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::process::ExitCode;

use clap::{ArgAction, Parser, Subcommand};
use vmm_sys_util::ioctl::ioctl_with_val;
use vmm_sys_util::ioctl_io_nr;

const TACHYON_CTRL_IO: u32 = 0xAE;
ioctl_io_nr!(TACHYON_IOC_CREATE_PARTITION, TACHYON_CTRL_IO, 0x01);
ioctl_io_nr!(TACHYON_IOC_DESTROY_PARTITION, TACHYON_CTRL_IO, 0x02);

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Command line tool for managing virtio-vm partitions",
    long_about = None
)]
#[command(arg_required_else_help = true)]
struct Cli {
    /// Path to the tachyon control device
    #[arg(short, long, default_value = "/dev/tachyon-ctrl", global = true)]
    device: String,

    #[command(subcommand)]
    command: Commands,

    /// Sets the level of debugging output
    #[arg(short, action = ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new partition device node in devtmpfs (/dev/tachyon-<partition_id>/kvm)
    #[command(name = "partition-create")]
    PartitionCreate {
        /// Partition identifier (UID)
        partition_id: u64,
    },
    /// Destroy an existing partition device
    #[command(name = "partition-destroy")]
    PartitionDestroy {
        /// Partition identifier (UID)
        partition_id: u64,
    },
}

fn partition_create(dev_path: &str, partition_id: u64) -> Result<(), std::io::Error> {
    let file = OpenOptions::new().read(true).write(true).open(dev_path)?;

    let ret = unsafe { ioctl_with_val(&file, TACHYON_IOC_CREATE_PARTITION(), partition_id) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn partition_destroy(dev_path: &str, partition_id: u64) -> Result<(), std::io::Error> {
    let file = OpenOptions::new().read(true).write(true).open(dev_path)?;

    let ret = unsafe { ioctl_with_val(&file, TACHYON_IOC_DESTROY_PARTITION(), partition_id) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::PartitionCreate { partition_id } => {
            if let Err(e) = partition_create(&cli.device, partition_id) {
                eprintln!(
                    "Error creating partition {} using {}: {}",
                    partition_id, cli.device, e
                );
                return ExitCode::FAILURE;
            }
            println!(
                "Partition {} created successfully (/dev/tachyon-{}/kvm)",
                partition_id, partition_id
            );
        }
        Commands::PartitionDestroy { partition_id } => {
            if let Err(e) = partition_destroy(&cli.device, partition_id) {
                eprintln!(
                    "Error destroying partition {} using {}: {}",
                    partition_id, cli.device, e
                );
                return ExitCode::FAILURE;
            }
            println!("Partition {} destroyed successfully", partition_id);
        }
    }

    ExitCode::SUCCESS
}
