// ============================================================
// Мостик в grammers: MtProxyTransport, реализующий
// grammers_mtproto::transport::Transport — тот же алгоритм, что и
// MtProxyCodec, но в терминах grammers (DequeBuffer/UnpackedOffset).
//
// Активируется фичей "grammers":
//   mtproto-client-rust = { version = "0.1", features = ["grammers"] }
//
// ВАЖНО: grammers-mtsender сам подключается к адресам датацентров и
// не умеет MTProto-прокси из коробки — нужно пропатчить место
// подключения (подставить адрес прокси). Рабочий пример патча:
// https://github.com/.../hawthorn-bot-rust (vendor/grammers-mtsender).
// ============================================================

use aes::cipher::{KeyIvInit as _, StreamCipher as _};
use grammers_mtproto::transport::{Error, Transport, UnpackedOffset};
use grammers_mtproto::DequeBuffer;
use sha2::{Digest as _, Sha256};

use crate::init::generate_init;
use crate::secret::MtProxySecret;

type Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Транспорт MTProto-прокси для grammers (аналог
/// ConnectionTcpMTProxyRandomizedIntermediate в Telethon).
///
/// ```no_run
/// use grammers_mtproto::mtp;
/// use mtproto_client_rust::{MtProxySecret, grammers_transport::MtProxyTransport};
///
/// // Транспорт MTProto-прокси (аналог ConnectionTcpMTProxyRandomizedIntermediate):
/// let secret = MtProxySecret::parse("0123456789abcdef0123456789abcdef").unwrap();
/// let _transport = MtProxyTransport::from_secret(&secret, 2);
/// ```
pub struct MtProxyTransport {
    /// AES-256-CTR исходящего трафика (клиент -> сервер).
    tx: Ctr,
    /// AES-256-CTR входящего трафика (сервер -> клиент).
    rx: Ctr,
    /// 64-байтовый init-пейлоад: первые 56 байт открытым текстом, байты
    /// 56..64 — уже зашифрованы (тег + dc_id). Отправляется разово
    /// перед первым пакетом.
    head: Option<Vec<u8>>,
    /// Сколько байтов входного буфера уже расшифровано.
    decrypt_tail: usize,
}

impl std::fmt::Debug for MtProxyTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ключи шифрования не выводим.
        f.debug_struct("MtProxyTransport")
            .field("head_pending", &self.head.is_some())
            .field("decrypt_tail", &self.decrypt_tail)
            .finish()
    }
}

impl MtProxyTransport {
    /// Транспорт MTProto-прокси: `secret` — нормализованный 16-байтовый
    /// секрет прокси, `dc_id` — датацентр, к которому прокси
    /// маршрутизирует трафик.
    pub fn new(secret: [u8; 16], dc_id: i32) -> Self {
        Self::from_init(generate_init(secret, dc_id), secret)
    }

    /// Транспорт из MtProxySecret (удобно после parse из .env).
    pub fn from_secret(secret: &MtProxySecret, dc_id: i32) -> Self {
        Self::new(*secret.as_bytes(), dc_id)
    }

    /// Сборка транспорта из готового init-пейлоада (используется тестами).
    pub(crate) fn from_init(init: [u8; 64], secret: [u8; 16]) -> Self {
        // Telethon шифрует ВСЕ 64 байта init и кладёт обратно только хвост
        // 56..64 — keystream к моменту первого пакета потреблён на 64 байта.
        let mut cipher = Self::tx_cipher(&init, &secret);
        let mut encrypted = init;
        cipher.apply_keystream(&mut encrypted);

        let mut head = Vec::with_capacity(64);
        head.extend_from_slice(&init[0..56]);
        head.extend_from_slice(&encrypted[56..64]);

        Self {
            tx: cipher,
            rx: Self::rx_cipher(&init, &secret),
            head: Some(head),
            decrypt_tail: 0,
        }
    }

    /// Ключ шифрования (клиент -> сервер): sha256(init[8:40] ++ secret),
    /// iv = init[40:56]. Дословно MTProxyIO.init_header из Telethon.
    pub(crate) fn tx_cipher(init: &[u8; 64], secret: &[u8; 16]) -> Ctr {
        let mut hasher = Sha256::new();
        hasher.update(&init[8..40]);
        hasher.update(secret);
        Ctr::new(
            hasher.finalize().as_slice().try_into().unwrap(),
            init[40..56].try_into().unwrap(),
        )
    }

    /// Ключ расшифровки (сервер -> клиент): sha256(reverse(init[8:56])[0..32] ++ secret),
    /// iv = reverse(init[8:56])[32..48] (дословно random_reversed из Telethon).
    pub(crate) fn rx_cipher(init: &[u8; 64], secret: &[u8; 16]) -> Ctr {
        let mut reversed = [0u8; 48];
        for i in 0..48 {
            reversed[i] = init[55 - i];
        }
        let mut hasher = Sha256::new();
        hasher.update(&reversed[0..32]);
        hasher.update(secret);
        Ctr::new(
            hasher.finalize().as_slice().try_into().unwrap(),
            reversed[32..48].try_into().unwrap(),
        )
    }
}

impl Transport for MtProxyTransport {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        let len = buffer.len();
        assert_eq!(len % 4, 0);

        // randomized intermediate: 0..3 байта случайного паддинга в конце,
        // поле длины включает паддинг
        let pad_len = (rand::random::<u8>() % 4) as usize;
        let mut pad = [0u8; 3];
        crate::init::rand_fill(&mut pad[..pad_len]);
        buffer.extend_back(&pad[..pad_len]);

        let total = (len + pad_len) as i32;
        buffer.extend_front(&total.to_le_bytes());

        // шифруем весь видимый кадр (длина + данные + паддинг) на месте
        self.tx.apply_keystream(buffer.as_mut());

        // 64-байтовый init перед первым пакетом — открытым текстом
        if let Some(head) = self.head.take() {
            buffer.extend_front(&head);
        }
    }

    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.len() < self.decrypt_tail {
            panic!("buffer is smaller than what was decrypted");
        }

        self.rx.apply_keystream(&mut buffer[self.decrypt_tail..]);
        self.decrypt_tail = buffer.len();

        if buffer.len() < 4 {
            return Err(Error::MissingBytes);
        }

        let len = i32::from_le_bytes(buffer[0..4].try_into().unwrap());
        if (buffer.len() as i32) < len {
            return Err(Error::MissingBytes);
        }

        if len <= 4 {
            if len >= 4 {
                // транспортная ошибка: статус в следующих 4 байтах (len == 4)
                let data = i32::from_le_bytes(buffer[4..8].try_into().unwrap());
                return Err(Error::BadStatus { status: (-data) as u32 });
            }
            if len < 0 {
                // транспортные ошибки передаются отрицательной длиной
                return Err(Error::BadStatus { status: (-len) as u32 });
            }
            return Err(Error::BadLen { got: len });
        }

        const MAX_PACKET_SIZE: i32 = 0xff000;
        if len > MAX_PACKET_SIZE {
            return Err(Error::BadLen { got: len });
        }

        let len = len as usize;
        // randomized intermediate: len % 4 байт паддинга в конце пакета
        let payload_len = len - (len % 4);

        let offset = UnpackedOffset {
            data_range: 4..4 + payload_len,
            next_offset: 4 + len,
        };
        self.decrypt_tail -= offset.next_offset;
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 16] = [0x11u8; 16];

    fn test_transport() -> (MtProxyTransport, [u8; 64]) {
        let init = generate_init(TEST_SECRET, 2);
        (MtProxyTransport::from_init(init, TEST_SECRET), init)
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as i32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    struct SimulatedServer {
        client_rx: Ctr,
        client_tx: Ctr,
    }

    impl SimulatedServer {
        fn from_init(init: &[u8; 64], secret: &[u8; 16]) -> Self {
            let mut client_tx_view = MtProxyTransport::tx_cipher(init, secret);
            let mut handshake = *init;
            client_tx_view.apply_keystream(&mut handshake);

            SimulatedServer {
                client_rx: client_tx_view,
                client_tx: MtProxyTransport::rx_cipher(init, secret),
            }
        }

        fn receive(&mut self, wire: &[u8]) -> Vec<u8> {
            let mut data = wire.to_vec();
            self.client_rx.apply_keystream(&mut data);
            data
        }

        fn send(&mut self, payload: &[u8]) -> Vec<u8> {
            let mut data = payload.to_vec();
            self.client_tx.apply_keystream(&mut data);
            data
        }
    }

    #[test]
    fn roundtrip_client_to_server() {
        let (mut client, init) = test_transport();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let payload: Vec<u8> = (0..64u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut buf = DequeBuffer::with_capacity(payload.len(), 0);
        buf.extend_back(&payload);
        client.pack(&mut buf);
        let wire = buf.as_ref().to_vec();

        assert!(wire.len() >= 64 + 4 + payload.len() && wire.len() <= 64 + 4 + payload.len() + 3);
        assert_eq!(&wire[0..56], &init[0..56]);
        assert_ne!(&wire[56..64], &init[56..64]);

        let frame = server.receive(&wire[64..]);
        let framed_len = i32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert!(framed_len >= payload.len() && framed_len <= payload.len() + 3);
        assert_eq!(&frame[4..4 + payload.len()], &payload[..]);

        let second = [7u8, 0, 0, 0, 1, 2, 3, 4];
        let mut buf2 = DequeBuffer::with_capacity(8, 0);
        buf2.extend_back(&second);
        client.pack(&mut buf2);
        let wire2 = buf2.as_ref().to_vec();
        let frame2 = server.receive(&wire2);
        let framed_len2 = i32::from_le_bytes(frame2[0..4].try_into().unwrap()) as usize;
        assert!(framed_len2 >= 8 && framed_len2 <= 11);
        assert_eq!(&frame2[4..12], &second);
    }

    #[test]
    fn roundtrip_server_to_client() {
        let (mut client, init) = test_transport();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let server_payload: Vec<u8> = (0..25u32).flat_map(|i| i.to_le_bytes()).collect();
        let wire = server.send(&framed(&server_payload));

        let mut seg = wire.clone();
        let offset = client.unpack(&mut seg).unwrap();
        assert_eq!(offset.next_offset, 104);
        assert_eq!(offset.data_range.len(), 100);
        assert_eq!(&seg[offset.data_range], &server_payload[..]);
    }

    #[test]
    fn unpack_two_packets_at_once() {
        let (mut client, init) = test_transport();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let mut all = Vec::new();
        for chunk in [vec![1u8; 64], vec![2u8; 36], vec![3u8; 12]] {
            all.extend_from_slice(&server.send(&framed(&chunk)));
        }

        let mut seg = all;
        let mut consumed = 0usize;
        let mut seen = Vec::new();
        while consumed < seg.len() {
            let offset = client.unpack(&mut seg[consumed..]).unwrap();
            seen.push(seg[consumed + offset.data_range.start]);
            consumed += offset.next_offset;
        }
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn unpack_missing_bytes() {
        let (mut client, init) = test_transport();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let payload = vec![9u8; 48];
        let wire = server.send(&framed(&payload));
        let mut seg = wire[..30].to_vec();
        assert_eq!(client.unpack(&mut seg), Err(Error::MissingBytes));
        seg.extend_from_slice(&wire[30..]);
        let offset = client.unpack(&mut seg).unwrap();
        assert_eq!(&seg[offset.data_range], &payload[..]);
    }

    #[test]
    fn unpack_bad_status_negative_len() {
        let (mut client, init) = test_transport();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);
        let mut err_bytes = (-404i32).to_le_bytes().to_vec();
        err_bytes.extend_from_slice(&0i32.to_le_bytes());
        let wire = server.send(&err_bytes);
        let mut seg = wire;
        assert_eq!(client.unpack(&mut seg), Err(Error::BadStatus { status: 404 }));
    }

    #[test]
    fn from_secret_matches_new() {
        let secret = MtProxySecret::parse("0123456789abcdef0123456789abcdef").unwrap();
        let t1 = MtProxyTransport::from_secret(&secret, 2);
        let t2 = MtProxyTransport::new(*secret.as_bytes(), 2);
        // разные init, но структура одинакова — просто проверяем типы
        let _ = (t1, t2);
    }
}
