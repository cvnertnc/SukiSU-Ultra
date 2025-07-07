use anyhow::{Result, ensure};
use std::io::{Read, Seek, SeekFrom};

pub fn get_apk_signature(apk: &str) -> Result<(u32, String)> {
    let mut buffer = [0u8; 0x10];
    let mut size4 = [0u8; 4];
    let mut size8 = [0u8; 8];
    let mut size_of_block = [0u8; 8];

    let mut f = std::fs::File::open(apk)?;

    let mut i = 0;
    loop {
        let mut n = [0u8; 2];
        f.seek(SeekFrom::End(-i - 2))?;
        f.read_exact(&mut n)?;

        let n = u16::from_le_bytes(n);
        if i64::from(n) == i {
            f.seek(SeekFrom::Current(-22))?;
            f.read_exact(&mut size4)?;

            if u32::from_le_bytes(size4) ^ 0xcafe_babe_u32 == 0xccfb_f1ee_u32 {
                if i > 0 {
                    log::warn!("Comment length is {}", i);
                }
                break;
            }
        }

        ensure!(n != 0xffff, "not a zip file");

        i += 1;
    }

    f.seek(SeekFrom::Current(12))?;
    // offset
    f.read_exact(&mut size4)?;
    f.seek(SeekFrom::Start(u64::from(u32::from_le_bytes(size4)) - 0x18))?;

    f.read_exact(&mut size8)?;
    f.read_exact(&mut buffer)?;

    ensure!(&buffer == b"APK Sig Block 42", "Cannot find signature block");

    let pos = u64::from(u32::from_le_bytes(size4)) - (u64::from_le_bytes(size8) + 0x8);
    f.seek(SeekFrom::Start(pos))?;
    f.read_exact(&mut size_of_block)?;

    ensure!(size_of_block == size8, "not a signed apk");

    let mut v2_signing: Option<(u32, String)> = None;
    let mut v3_signing: Option<(u32, String)> = None;
    let mut v3_1_signing: Option<(u32, String)> = None;

    // Store current position to reset for v3 parsing
    let block_start_pos = f.stream_position()?;

    loop {
        let mut id = [0u8; 4];
        let mut offset = 4u32;

        f.read_exact(&mut size8)?; // sequence length
        if size8 == size_of_block {
            break;
        }

        f.read_exact(&mut id)?; // id

        let id = u32::from_le_bytes(id);
        if id == 0x7109_871a_u32 {
            // v2 signature scheme
            v2_signing = Some(calc_cert_sha256(&mut f, &mut size4, &mut offset)?);
            log::info!("Found v2 signature");
        } else if id == 0xf053_68c0_u32 {
            // v3 signature scheme
            log::info!("Found v3 signature");
            // We'll parse v3 in a second pass if needed
        } else if id == 0x1b93_ad61_u32 {
            // v3.1 signature scheme: credits to vvb2060
            log::info!("Found v3.1 signature");
            // We'll parse v3.1 in a second pass if needed
        }

        f.seek(SeekFrom::Current(
            i64::from_le_bytes(size8) - i64::from(offset),
        ))?;
    }

    // If v2 signature exists, return it (preferred)
    if let Some(v2_sig) = v2_signing {
        log::info!("Using v2 signature");
        return Ok(v2_sig);
    }

    // If no v2 signature, try to parse v3/v3.1 signatures
    log::info!("No v2 signature found, attempting to parse v3/v3.1 signatures");
    
    // Reset to block start for v3 parsing
    f.seek(SeekFrom::Start(block_start_pos))?;

    loop {
        let mut id = [0u8; 4];
        let mut offset = 4u32;

        f.read_exact(&mut size8)?; // sequence length
        if size8 == size_of_block {
            break;
        }

        f.read_exact(&mut id)?; // id

        let id = u32::from_le_bytes(id);
        if id == 0xf053_68c0_u32 {
            // v3 signature scheme
            v3_signing = Some(calc_v3_cert_sha256(&mut f, &mut size4, &mut offset)?);
        } else if id == 0x1b93_ad61_u32 {
            // v3.1 signature scheme
            v3_1_signing = Some(calc_v3_cert_sha256(&mut f, &mut size4, &mut offset)?);
        }

        f.seek(SeekFrom::Current(
            i64::from_le_bytes(size8) - i64::from(offset),
        ))?;
    }

    // Prefer v3.1 over v3, then v3 over nothing
    if let Some(v3_1_sig) = v3_1_signing {
        log::info!("Using v3.1 signature");
        return Ok(v3_1_sig);
    }

    if let Some(v3_sig) = v3_signing {
        log::info!("Using v3 signature");
        return Ok(v3_sig);
    }

    Err(anyhow::anyhow!("No signature found"))
}

fn calc_cert_sha256(
    f: &mut std::fs::File,
    size4: &mut [u8; 4],
    offset: &mut u32,
) -> Result<(u32, String)> {
    f.read_exact(size4)?; // signer-sequence length
    f.read_exact(size4)?; // signer length
    f.read_exact(size4)?; // signed data length
    *offset += 0x4 * 3;

    f.read_exact(size4)?; // digests-sequence length
    let pos = u32::from_le_bytes(*size4); // skip digests
    f.seek(SeekFrom::Current(i64::from(pos)))?;
    *offset += 0x4 + pos;

    f.read_exact(size4)?; // certificates length
    f.read_exact(size4)?; // certificate length
    *offset += 0x4 * 2;

    let cert_len = u32::from_le_bytes(*size4);
    let mut cert: Vec<u8> = vec![0; cert_len as usize];
    f.read_exact(&mut cert)?;
    *offset += cert_len;

    Ok((cert_len, sha256::digest(&cert)))
}

fn calc_v3_cert_sha256(
    f: &mut std::fs::File,
    size4: &mut [u8; 4],
    offset: &mut u32,
) -> Result<(u32, String)> {
    // v3 signature block structure is different from v2
    // Skip the signed data length
    f.read_exact(size4)?; // signed data length
    let signed_data_len = u32::from_le_bytes(*size4);
    *offset += 0x4;

    // Skip signed data
    f.seek(SeekFrom::Current(i64::from(signed_data_len)))?;
    *offset += signed_data_len;

    // Read certificates length
    f.read_exact(size4)?; // certificates length
    *offset += 0x4;

    // Read first certificate length
    f.read_exact(size4)?; // certificate length
    *offset += 0x4;

    let cert_len = u32::from_le_bytes(*size4);
    let mut cert: Vec<u8> = vec![0; cert_len as usize];
    f.read_exact(&mut cert)?;
    *offset += cert_len;

    log::debug!("Extracted v3 certificate with length: {}", cert_len);

    Ok((cert_len, sha256::digest(&cert)))
}