//! Записывает реальные кадры MimicryEngine в PCAP для независимой DPI-проверки.
use std::io::Write;

use aivpn_common::client_wire::build_inner_packet;
use aivpn_common::crypto::SessionKeys;
use aivpn_common::mask::MaskProfile;
use aivpn_common::mimicry::MimicryEngine;
use aivpn_common::protocol::InnerType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: maskpcap MASK.json OUTPUT.pcap".into());
    }
    let mask: MaskProfile = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let mut output = std::fs::File::create(&args[2])?;
    output.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    output.write_all(&2u16.to_le_bytes())?;
    output.write_all(&4u16.to_le_bytes())?;
    for value in [0u32, 0, 65535, 1] {
        output.write_all(&value.to_le_bytes())?;
    }
    let keys = SessionKeys {
        session_key: [1; 32],
        session_key_s2c: [2; 32],
        tag_secret: [3; 32],
        prng_seed: [4; 32],
    };
    let mut engine = MimicryEngine::new(mask);
    let mut counter = 0;
    for index in 0..100u16 {
        let data = vec![(index % 251) as u8; 80 + (usize::from(index) * 13 % 900)];
        let inner = build_inner_packet(InnerType::Data, index, &data);
        let eph = [17; 32];
        let wire = engine.build_packet(
            &inner,
            &keys,
            &mut counter,
            if index == 0 { Some(&eph) } else { None },
        )?;
        let packet = udp_frame(&wire);
        for value in [
            1_700_000_000u32,
            u32::from(index) * 1000,
            packet.len() as u32,
            packet.len() as u32,
        ] {
            output.write_all(&value.to_le_bytes())?;
        }
        output.write_all(&packet)?;
        engine.update_fsm();
    }
    Ok(())
}

fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 14 + 20 + 8];
    packet[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut packet[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
    let mut sum: u32 = ip
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet[34..36].copy_from_slice(&44999u16.to_be_bytes());
    packet[36..38].copy_from_slice(&443u16.to_be_bytes());
    packet[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
