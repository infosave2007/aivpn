/// 3f: human-readable message for a `HandshakeReject` reason code. See
/// `ControlPayload::HandshakeReject`'s doc comment in aivpn-common for the
/// authoritative mapping: 1=one-time key already used, 2=expired,
/// 3=disabled, 0/other=unspecified.
pub fn handshake_reject_message(reason: u8) -> &'static str {
    match reason {
        1 => "one-time key already used",
        2 => "client expired",
        3 => "client disabled",
        _ => "refused",
    }
}

/// 3f: short machine-readable token for the `AIVPN-STATUS rejected <token>`
/// stdout line — mirrors `handshake_reject_message` but as an ASCII token a
/// GUI can match without depending on the English wording (the GUI maps the
/// token to its own localized string).
pub(super) fn handshake_reject_token(reason: u8) -> &'static str {
    match reason {
        1 => "one_time_used",
        2 => "expired",
        3 => "disabled",
        _ => "unspecified",
    }
}
