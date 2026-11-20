use super::*;

fn response() -> [u8; STATUS_BYTES] {
    let mut bytes = [0u8; STATUS_BYTES];
    bytes[0] = 1;
    bytes[4] = 48;
    bytes[8] = 9;
    bytes[36] = 1;
    bytes
}

#[test]
fn response_must_describe_one_inactive_staging_session() {
    let empty = response();
    assert_eq!(decode_status(&empty).unwrap().state, StagedState::Empty);
    let mut staged = empty;
    staged[24] = 7;
    staged[32] = 1;
    let status = decode_status(&staged).unwrap();
    assert_eq!(status.session.get(), 9);
    assert_eq!(status.generation.unwrap().get(), 7);
    assert_eq!(status.state, StagedState::PolicyStaged);
    for offset in [0, 4, 8, 16, 20, 24, 32, 36, 40, 44] {
        let mut bad = empty;
        bad[offset] = if offset == 8 { 0 } else { 2 };
        assert!(decode_status(&bad).is_err(), "offset={offset}");
    }
    let mut missing_generation = staged;
    missing_generation[24] = 0;
    assert!(decode_status(&missing_generation).is_err());
}
