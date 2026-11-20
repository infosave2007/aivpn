fn checksum(bytes: &[u8]) -> u16 {
    let sum = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    let folded = (sum & 0xffff) + (sum >> 16);
    !((folded & 0xffff) + (folded >> 16)) as u16
}

pub fn reply(packet: &mut [u8], ipv6: bool) {
    if ipv6 {
        assert_eq!(packet[6], 58);
        assert_eq!(packet[40], 128);
        let source: [u8; 16] = packet[8..24].try_into().unwrap();
        packet.copy_within(24..40, 8);
        packet[24..40].copy_from_slice(&source);
        packet[40] = 129;
        packet[42..44].fill(0);
        let mut pseudo = packet[8..40].to_vec();
        pseudo.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&packet[40..]);
        packet[42..44].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    } else {
        assert_eq!(packet[9], 1);
        assert_eq!(packet[20], 8);
        let source: [u8; 4] = packet[12..16].try_into().unwrap();
        packet.copy_within(16..20, 12);
        packet[16..20].copy_from_slice(&source);
        packet[10..12].fill(0);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet[20] = 0;
        packet[22..24].fill(0);
        let sum = checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&sum.to_be_bytes());
    }
}
