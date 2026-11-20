//! Проверка границ всех подтипов управляющих сообщений на постоянном корпусе.
use aivpn_common::protocol::ControlPayload;

#[test]
fn every_control_subtype_handles_short_and_adversarial_lengths_without_panics() {
    let mut seed = 0x7bd5_1529_u32;
    for subtype in 0..=u8::MAX {
        for length in [
            1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 16, 17, 31, 32, 33, 63, 64, 65, 96, 97, 127, 255, 256,
            1024,
        ] {
            for pattern in 0..4 {
                let mut packet = vec![0; length];
                for byte in &mut packet {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    *byte = match pattern {
                        0 => 0,
                        1 => 255,
                        2 => 1,
                        _ => seed as u8,
                    };
                }
                packet[0] = subtype;
                if let Ok(decoded) = ControlPayload::decode(&packet) {
                    let encoded = decoded.encode().unwrap_or_else(|error| {
                        panic!("subtype={subtype}, len={length}, pattern={pattern}: {error}")
                    });
                    let repeated = ControlPayload::decode(&encoded)
                        .expect("Принятое сообщение должно читаться после кодирования");
                    assert_eq!(
                        repeated.encode().unwrap(),
                        encoded,
                        "subtype={subtype}, len={length}, pattern={pattern}"
                    );
                }
            }
        }
    }
}
