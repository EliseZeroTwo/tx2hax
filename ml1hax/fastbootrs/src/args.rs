use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing::Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}

#[derive(clap::Parser)]
#[command(version)]
pub struct CliArgs {
    /// Optional log level, can also be set by the "FBRS_TRACE" environment variable. If both are specified, the environment variable is preferred.
    #[arg(long)]
    pub log_level: Option<LogLevel>,

    /// Optionally select the serial number of the device to operate on. This is required if multiple fastboot devices are connected.
    #[arg(short, long)]
    pub serial: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

fn parse_hex(input: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(input.strip_prefix("0x").unwrap_or(input), 16)
}

fn parse_instr(input: &str) -> Result<[u8; 4], std::num::ParseIntError> {
    match input.strip_prefix("0x") {
        Some(input) => u32::from_str_radix(input, 16).map(|x| x.to_le_bytes()),
        None => u32::from_str_radix(input, 16).map(|x| x.to_be_bytes()),
    }
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Show a list of connected devices and their serial numbers
    Devices,
    /// Continue boot
    Continue,
    ExploitHuntBytes {
        #[clap(value_parser = parse_hex)]
        base: Option<u32>,
    },
    ExploitHuntInstruction {
        #[clap(long="start", value_parser = parse_hex)]
        start_address: Option<u32>,
        #[clap(value_parser = parse_instr)]
        instruction: [u8; 4],
    },
    Exploit,
    ReadU32 {
        #[clap(value_parser = parse_hex)]
        address: u32,
    },
    Poweroff,
    Reboot {
        #[clap(subcommand)]
        mode: Option<RebootType>,
    },
    DumpMemory {
        #[clap(value_parser = parse_hex)]
        address: u32,
        #[clap(value_parser = parse_hex)]
        length: u32,
    },
    DumpQspi,
    DumpFlash {
        /// Sector start
        sector_start: u64,
        /// Sector count
        sector_count: u64,
    },
    Fuse {
        #[clap(subcommand)]
        fuse_type: FuseType,
    },
    RawFuse {
        #[clap(value_parser = parse_hex)]
        offset: u32,
    },
    SeHax {
        #[clap(short, long)]
        validate: bool,
        #[clap(short, long)]
        vectors: bool,
        #[clap(short, long)]
        test: bool,
    },
    ReadKeys,
    ReadSysram,
    Partitions {
        #[clap(short, long)]
        qspi: bool,
    },
    DumpPartition {
        #[clap(short, long)]
        qspi: bool,
        partition: String,
        out_dir: Option<PathBuf>,
    },
    Dtbhax,
}

#[derive(clap::Subcommand)]
pub enum PartitionSource {
    Ufs,
    Qspi,
}

#[derive(clap::Subcommand)]
pub enum FuseType {
    BootSecurityInfo = 0x0,
    SecBootDev = 0x1,
    UID = 0x2,
    SkuInfo = 0x3,
    TID = 0x4,
    CpuSpeedo0 = 0x5,
    CpuSpeedo1 = 0x6,
    CpuSpeedo2 = 0x7,
    CpuIddq = 0x8,
    SocSpeedo0 = 0x9,
    SocSpeedo1 = 0xa,
    SocSpeedo2 = 0xb,
    EnabledCpuCores = 0xc,
    TpcDisable,
    Apb2JtagLock,
    SocIddq,
    SataNvCalib,
    SataMphyOdmCalib,
    TSensor9Calib,
    TSensorCommonT1,
    TSensorCommonT2,
    TSensorCommonT3,
    HyperVoltaging,
    ReservedCalib0,
    OptPrivSecEn,
    UsbCalib,
    UsbCalibExt,
    ProductionMode,
    SecurityMode,
    OdmLock,
    ArmJtagDis,
    ReservedOdm0,
    ReservedOdm1,
    ReservedOdm2,
    ReservedOdm3,
    ReservedOdm4,
    ReservedOdm5,
    ReservedOdm6,
    ReservedOdm7,
    KEK256,
    KEK2,
    PkcPubkeyHash,
    SecureBootKey,
    ReservedSw,
    BootDeviceSelect,
    SkipDevSelStraps,
    BootDeviceInfo,
    KEK0,
    KEK1,
    EndorsementKey,
    ODMID,
    H2,
    OdmInfo,
    DebugAuthentication,
    CcplexDfdAccessDisable,
}

#[derive(clap::Subcommand)]
pub enum RebootType {
    /// Reboot back to standard ML fastboot
    Fastboot,
    /// Reboot to RCM
    ForcedRecovery,
    /// Reboot and attempt to get MB2 to enter into 3P mode
    ThreeP,
}
