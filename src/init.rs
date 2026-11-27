// ============================================================
// init-пейлоад handshake — дословный порт MTProxyIO.init_header
// из Telethon (tcpmtproxy.py).
// ============================================================

/// Запрещённые первые 4 байта init-пейлоада (не должны выглядеть как HTTP/TLS),
/// а также первый байт 0xef (зарезервирован abridged-транспортом).
pub(crate) const FORBIDDEN_PREFIXES: [[u8; 4]; 4] =
    [*b"PVrG", *b"GET ", *b"POST", [0xee, 0xee, 0xee, 0xee]];

/// Тег randomized-intermediate внутри init-пейлоада.
pub(crate) const MTPROXY_TAG: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// Генерация 64-байтового init-пейлоада:
///   • байты 0..56 — случайные (без запрещённых префиксов);
///   • байты 56..60 — тег dd dd dd dd;
///   • байты 60..62 — dc_id (i16, little-endian);
///   • байты 62..64 — случайные.
///
/// Первые 56 байт уйдут в сеть открытым текстом, хвост 56..64
/// шифруется (см. MtProxyCodec::with_init).
pub fn generate_init(_secret: [u8; 16], dc_id: i32) -> [u8; 64] {
    let mut init = [0u8; 64];
    loop {
        rand_fill(&mut init);
        if init[0] == 0xef || FORBIDDEN_PREFIXES.iter().any(|p| init[0..4] == *p) {
            continue;
        }
        break;
    }
    init[56..60].copy_from_slice(&MTPROXY_TAG);
    // dc_id: 2 байта, little-endian, signed (dc_id.to_bytes(2, "little", signed=True))
    init[60..62].copy_from_slice(&(dc_id as i16).to_le_bytes());
    // байты 62..64 остаются случайными
    init
}

pub(crate) fn rand_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_header_invariants() {
        let secret = [0xau8; 16];
        let init = generate_init(secret, 5);
        assert_eq!(init.len(), 64);
        assert_eq!(&init[56..60], &MTPROXY_TAG);
        let dc = i16::from_le_bytes([init[60], init[61]]);
        assert_eq!(dc, 5);
        assert_ne!(init[0], 0xef);
        // первый байт не образует запрещённых префиксов
        assert!(!FORBIDDEN_PREFIXES.iter().any(|p| init[0..4] == *p));
    }

    #[test]
    fn init_header_distinct_each_call() {
        let secret = [0xau8; 16];
        let a = generate_init(secret, 2);
        let b = generate_init(secret, 2);
        assert_ne!(a.to_vec(), b.to_vec());
    }

    #[test]
    fn dc_id_negative() {
        // отрицательный dc_id тоже должен упаковываться в i16
        let init = generate_init([0u8; 16], -3);
        assert_eq!(i16::from_le_bytes([init[60], init[61]]), -3);
    }
}
