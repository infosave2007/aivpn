//! Согласование TCP MSS с бюджетом маски, который может быть меньше MTU TUN.

pub(super) fn clamp(packet: &mut [u8], maximum_ip_size: usize) {
    let Some((tcp, fixed_headers)) = tcp_syn_header(packet) else {
        return;
    };
    let Some(option) = mss_option(&packet[tcp.start + 20..tcp.end]) else {
        return;
    };
    let mss_at = tcp.start + 20 + option;
    let old = u16::from_be_bytes([packet[mss_at], packet[mss_at + 1]]);
    let Some(maximum) = maximum_ip_size
        .checked_sub(fixed_headers)
        .filter(|maximum| *maximum >= 64)
        .and_then(|maximum| u16::try_from(maximum).ok())
    else {
        return;
    };
    if old <= maximum {
        return;
    }
    packet[mss_at..mss_at + 2].copy_from_slice(&maximum.to_be_bytes());
    let checksum_at = tcp.start + 16;
    let checksum = u16::from_be_bytes([packet[checksum_at], packet[checksum_at + 1]]);
    let updated = replace_checksum_word(checksum, old, maximum, mss_at % 2 == 0);
    packet[checksum_at..checksum_at + 2].copy_from_slice(&updated.to_be_bytes());
}

fn tcp_syn_header(packet: &[u8]) -> Option<(std::ops::Range<usize>, usize)> {
    let Some(parsed) = aivpn_common::ip_packet::IpPacket::parse(packet) else {
        return None;
    };
    let (offset, fixed_headers) = match packet[0] >> 4 {
        4 if packet[9] == 6 && u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff == 0 => {
            (usize::from(packet[0] & 15) * 4, 40)
        }
        6 if packet[6] == 6 => (40, 60),
        _ => return None,
    };
    if offset + 20 > parsed.length || packet[offset + 13] & 2 == 0 {
        return None;
    }
    let tcp_header = usize::from(packet[offset + 12] >> 4) * 4;
    if tcp_header < 20 || offset + tcp_header > parsed.length {
        return None;
    }
    Some((offset..offset + tcp_header, fixed_headers))
}

fn replace_checksum_word(checksum: u16, old: u16, new: u16, aligned: bool) -> u16 {
    // RFC 1624: меняем только вклад MSS, не исправляя постороннее повреждение.
    let (old_word, new_word) = if aligned {
        (old, new)
    } else {
        (old.swap_bytes(), new.swap_bytes())
    };
    let mut sum = u32::from(!checksum) + u32::from(!old_word) + u32::from(new_word);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn mss_option(options: &[u8]) -> Option<usize> {
    let mut found = None;
    let mut position = 0;
    while position < options.len() {
        let kind = options[position];
        match kind {
            0 => break,
            1 => {
                position += 1;
                continue;
            }
            // Подпись TCP MD5/AO нельзя пересчитать без ключа конечного узла.
            19 | 29 => return None,
            _ => {}
        }
        let length = usize::from(*options.get(position + 1)?);
        if length < 2 || position + length > options.len() {
            return None;
        }
        if kind == 2 {
            if length != 4 || found.is_some() {
                return None;
            }
            found = Some(position + 2);
        }
        position += length;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(ipv6: bool, options: &[u8]) -> Vec<u8> {
        let ip = if ipv6 { 40 } else { 20 };
        let mut packet = vec![0; ip + 20 + options.len()];
        let length = packet.len();
        if ipv6 {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
            packet[6] = 6;
            packet[23] = 1;
            packet[39] = 2;
        } else {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            packet[9] = 6;
            packet[15] = 1;
            packet[19] = 2;
        }
        packet[ip + 12] = (((20 + options.len()) / 4) as u8) << 4;
        packet[ip + 13] = 2;
        packet[ip + 20..].copy_from_slice(options);
        let checksum = tcp_checksum(&packet, ipv6);
        packet[ip + 16..ip + 18].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    // Независимый подсчет по псевдозаголовку и полному TCP-сегменту.
    fn tcp_checksum(packet: &[u8], ipv6: bool) -> u16 {
        let ip = if ipv6 { 40 } else { 20 };
        let addresses = if ipv6 {
            &packet[8..40]
        } else {
            &packet[12..20]
        };
        let mut bytes = addresses.to_vec();
        bytes.extend_from_slice(&((packet.len() - ip) as u32).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 6]);
        bytes.extend_from_slice(&packet[ip..]);
        let mut sum: u64 = bytes
            .chunks(2)
            .map(|pair| ((pair[0] as u64) << 8) | u64::from(*pair.get(1).unwrap_or(&0)))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn syn_and_syn_ack_negotiate_one_mask_packet_with_valid_checksum() {
        for ipv6 in [false, true] {
            let ip = if ipv6 { 40 } else { 20 };
            for flags in [2, 18] {
                for options in [vec![2, 4, 5, 180], vec![1, 2, 4, 5, 180, 1, 1, 0]] {
                    let mut packet = syn(ipv6, &options);
                    packet[ip + 13] = flags;
                    packet[ip + 16..ip + 18].fill(0);
                    let checksum = tcp_checksum(&packet, ipv6);
                    packet[ip + 16..ip + 18].copy_from_slice(&checksum.to_be_bytes());
                    let mss_offset = ip + 20 + usize::from(options[0] == 1) + 2;
                    clamp(&mut packet, 1080);
                    let mss = u16::from_be_bytes([packet[mss_offset], packet[mss_offset + 1]]);
                    assert_eq!(usize::from(mss), 1080 - ip - 20);
                    assert_eq!(tcp_checksum(&packet, ipv6), 0);
                    let once = packet.clone();
                    clamp(&mut packet, 1080);
                    assert_eq!(packet, once);
                }
            }
        }
    }

    #[test]
    fn changing_mss_does_not_repair_an_unrelated_checksum_error() {
        let mut packet = syn(false, &[1, 2, 4, 5, 180, 1, 1, 0]);
        packet[21] ^= 1;
        assert_ne!(tcp_checksum(&packet, false), 0);
        clamp(&mut packet, 1080);
        assert_ne!(
            tcp_checksum(&packet, false),
            0,
            "Поврежденный TCP не должен становиться корректным после clamp"
        );
    }

    #[test]
    fn lower_mss_non_syn_fragments_and_authenticated_tcp_are_untouched() {
        let mut cases = vec![syn(false, &[2, 4, 1, 244]), syn(false, &[2, 4, 5, 180])];
        cases[1][33] = 16;
        let mut fragment = syn(false, &[2, 4, 5, 180]);
        fragment[6] = 0x20;
        cases.push(fragment);
        let mut ipv6_fragment = syn(true, &[2, 4, 5, 180]);
        ipv6_fragment[6] = 44;
        cases.push(ipv6_fragment);
        for kind in [19, 29] {
            cases.push(syn(false, &[2, 4, 5, 180, kind, 4, 0, 0]));
        }
        for options in [
            vec![2, 3, 5, 180],
            vec![2, 4, 5, 180, 8, 0, 0, 0],
            vec![2, 4, 5, 180, 2, 4, 5, 180],
        ] {
            cases.push(syn(false, &options));
        }
        for original in cases {
            let mut packet = original.clone();
            clamp(&mut packet, 1080);
            assert_eq!(packet, original);
        }
        for length in 0..44 {
            let original = syn(false, &[2, 4, 5, 180]);
            let mut truncated = original[..length].to_vec();
            clamp(&mut truncated, 1080);
            assert_eq!(truncated, original[..length]);
        }
    }
}
