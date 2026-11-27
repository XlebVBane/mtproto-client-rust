// ============================================================
// MtProxyCodec — tokio-util codec обфусцированного транспорта
// «randomized intermediate» (1:1 порт tcpmtproxy.py из Telethon).
//
// Encoder: длина (4 байта LE, включает 0..3 байта паддинга) + payload +
// паддинг, всё шифруется AES-256-CTR; перед первым кадром отправляется
// 64-байтовый init-пейлоад (56 байт открыто + 8 зашифрованно).
//
// Decoder: расшифровывает входной поток, снимает 4 байта длины и
// паддинг, отдаёт payload. Транспортные ошибки прокси (отрицательная
// длина / статус в следующих 4 байтах) -> MtProxyError::BadStatus.
// ============================================================

use aes::cipher::{KeyIvInit as _, StreamCipher as _};
use bytes::{BufMut as _, Bytes, BytesMut};
use sha2::{Digest as _, Sha256};

use crate::init::{generate_init, rand_fill};
use crate::secret::MtProxySecret;

type Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Максимальный размер транспортного пакета (как в grammers-mtproto).
pub(crate) const MAX_PACKET_SIZE: i32 = 0xff000;

/// Ошибки транспорта MTProto-прокси.
#[derive(Debug)]
pub enum MtProxyError {
    /// Прокси/датацентр сообщил о транспортной ошибке (код = -длина).
    /// Коды 404/407: неверный секрет, 429: flood и т.п.
    BadStatus { status: u32 },
    /// Некорректная длина кадра.
    BadLen { got: i32 },
    /// Ошибка ввода-вывода нижележащего соединения.
    Io(std::io::Error),
}

impl std::fmt::Display for MtProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MtProxyError::BadStatus { status } => {
                write!(f, "транспортная ошибка прокси (статус -{status})")
            }
            MtProxyError::BadLen { got } => write!(f, "некорректная длина кадра: {got}"),
            MtProxyError::Io(e) => write!(f, "ошибка соединения: {e}"),
        }
    }
}

impl std::error::Error for MtProxyError {}

impl From<std::io::Error> for MtProxyError {
    fn from(e: std::io::Error) -> Self {
        MtProxyError::Io(e)
    }
}

/// Кодек MTProto-прокси «randomized intermediate».
///
/// Используется через `tokio_util::codec::Framed` поверх любого
/// AsyncRead + AsyncWrite (обычно tokio TcpStream):
///
/// ```no_run
/// use mtproto_client_rust::{MtProxyCodec, MtProxySecret};
/// use tokio::net::TcpStream;
/// use tokio_util::codec::{Framed, Decoder as _};
/// use tokio_stream::StreamExt as _;
///
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// let secret = MtProxySecret::parse("0123456789abcdef0123456789abcdef")?;
/// let tcp = TcpStream::connect("127.0.0.1:443").await?;
/// let mut framed = Framed::new(tcp, MtProxyCodec::new(&secret, 2));
/// if let Some(frame) = framed.next().await { /* payload: bytes::Bytes */ }
/// # Ok(())
/// # }
/// ```
pub struct MtProxyCodec {
    /// AES-256-CTR исходящего трафика (клиент -> сервер).
    tx: Ctr,
    /// AES-256-CTR входящего трафика (сервер -> клиент).
    rx: Ctr,
    /// 64-байтовый init-пейлоад: первые 56 байт открытым текстом, байты
    /// 56..64 — уже зашифрованы (тег + dc_id). Отправляется разово
    /// перед первым пакетом.
    head: Option<Vec<u8>>,
    /// Сколько байтов входного буфера уже расшифровано (паттерн Obfuscated
    /// из grammers/Telethon: расшифровка продолжается по мере прихода данных).
    decrypt_tail: usize,
}

impl std::fmt::Debug for MtProxyCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ключи шифрования не выводим.
        f.debug_struct("MtProxyCodec")
            .field("head_pending", &self.head.is_some())
            .field("decrypt_tail", &self.decrypt_tail)
            .finish()
    }
}

impl MtProxyCodec {
    /// Кодек MTProto-прокси: `secret` — нормализованный секрет прокси,
    /// `dc_id` — датацентр, через который прокси маршрутизирует трафик
    /// (обычный клиент Telegram использует dc 2 или 5).
    pub fn new(secret: &MtProxySecret, dc_id: i32) -> Self {
        Self::with_init(generate_init(*secret.as_bytes(), dc_id), *secret.as_bytes())
    }

    /// Кодек из готового init-пейлоада (публично — для тестов и
    /// детерминированных сценариев).
    pub fn with_init(init: [u8; 64], secret: [u8; 16]) -> Self {
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

    /// Был ли уже отправлен init-пейлоад (для тестов).
    #[cfg(test)]
    pub(crate) fn head_sent(&self) -> bool {
        self.head.is_none()
    }
}

impl tokio_util::codec::Encoder<Bytes> for MtProxyCodec {
    type Error = MtProxyError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        assert_eq!(item.len() % 4, 0, "payload MTProto всегда кратен 4");

        // randomized intermediate: 0..3 байта случайного паддинга в конце,
        // поле длины включает паддинг
        let pad_len = (rand::random::<u8>() % 4) as usize;
        let mut pad = [0u8; 3];
        rand_fill(&mut pad[..pad_len]);

        let total = item.len() + pad_len;
        // шифруем весь видимый кадр (длина + данные + паддинг)
        let mut frame = Vec::with_capacity(4 + total);
        frame.extend_from_slice(&(total as i32).to_le_bytes());
        frame.extend_from_slice(&item);
        frame.extend_from_slice(&pad[..pad_len]);
        self.tx.apply_keystream(&mut frame);

        // 64-байтовый init перед первым пакетом — открытым текстом
        if let Some(head) = self.head.take() {
            dst.reserve(head.len() + frame.len());
            dst.put_slice(&head);
        } else {
            dst.reserve(frame.len());
        }
        dst.put_slice(&frame);
        Ok(())
    }
}

impl tokio_util::codec::Decoder for MtProxyCodec {
    type Item = Bytes;
    type Error = MtProxyError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < self.decrypt_tail {
            panic!("buffer is smaller than what was decrypted");
        }

        // расшифровываем только новые байты; уже расшифрованное — не трогаем
        self.rx.apply_keystream(&mut src[self.decrypt_tail..]);
        self.decrypt_tail = src.len();

        if src.len() < 4 {
            return Ok(None);
        }

        let len = i32::from_le_bytes(src[0..4].try_into().unwrap());

        if len < 0 {
            // транспортные ошибки передаются отрицательной длиной
            return Err(MtProxyError::BadStatus { status: (-len) as u32 });
        }
        if len > MAX_PACKET_SIZE {
            // fail fast: не буферизуем потенциально вредоносный объём
            return Err(MtProxyError::BadLen { got: len });
        }
        if (src.len() as i64) < 4i64 + len as i64 {
            return Ok(None); // MissingBytes — ждём остальное
        }

        if len <= 4 {
            if len == 4 {
                // транспортная ошибка: статус в следующих 4 байтах (len == 4)
                let data = i32::from_le_bytes(src[4..8].try_into().unwrap());
                return Err(MtProxyError::BadStatus { status: (-data) as u32 });
            }
            return Err(MtProxyError::BadLen { got: len });
        }

        let len = len as usize;
        // randomized intermediate: len % 4 байт паддинга в конце пакета
        let payload_len = len - (len % 4);
        let next_offset = 4 + len;

        let item = src.split_to(next_offset).freeze();
        let payload = item.slice(4..4 + payload_len);
        self.decrypt_tail -= next_offset;
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder as _, Encoder as _};

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as i32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// Сервер-симулятор: derives те же ключи, что настоящий MTProxy-сервер.
    pub(crate) struct SimulatedServer {
        /// Ключ, которым сервер расшифровывает клиентские пакеты
        /// (= tx клиента, продолжающийся после 64 байт хендшейка).
        client_rx: Ctr,
        /// Ключ, которым сервер шифрует ответы клиенту (= rx клиента).
        client_tx: Ctr,
    }

    impl SimulatedServer {
        pub(crate) fn from_init(init: &[u8; 64], secret: &[u8; 16]) -> Self {
            let mut client_tx_view = MtProxyCodec::tx_cipher(init, secret);
            // сервер читает 64 байта хендшейка: первые 56 — открытый текст,
            // хвост 56..64 расшифровывается ключом клиента
            let mut handshake = *init;
            client_tx_view.apply_keystream(&mut handshake);

            SimulatedServer {
                client_rx: client_tx_view,
                client_tx: MtProxyCodec::rx_cipher(init, secret),
            }
        }

        pub(crate) fn receive(&mut self, wire: &[u8]) -> Vec<u8> {
            let mut data = wire.to_vec();
            self.client_rx.apply_keystream(&mut data);
            data
        }

        pub(crate) fn send(&mut self, payload: &[u8]) -> Vec<u8> {
            let mut data = payload.to_vec();
            self.client_tx.apply_keystream(&mut data);
            data
        }
    }

    const TEST_SECRET: [u8; 16] = [0x11u8; 16];

    fn test_codec() -> (MtProxyCodec, [u8; 64]) {
        let init = generate_init(TEST_SECRET, 2);
        (MtProxyCodec::with_init(init, TEST_SECRET), init)
    }

    #[test]
    fn roundtrip_client_to_server() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        // первый encode добавляет 64-байтовый хендшейк
        let payload: Vec<u8> = (0..64u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut dst = BytesMut::new();
        client.encode(Bytes::from(payload.clone()), &mut dst).unwrap();
        let wire = &dst[..];

        // хендшейк: первые 56 байт открыты; хвост 56..64 зашифрован
        // (открытый тег в проводе не виден)
        assert!(wire.len() >= 64 + 4 + payload.len() && wire.len() <= 64 + 4 + payload.len() + 3);
        assert_eq!(&wire[0..56], &init[0..56]);
        assert_ne!(&wire[56..64], &init[56..64]);

        // сервер расшифровывает кадр: 4 байта длины + payload (без паддинга)
        let frame = server.receive(&wire[64..]);
        let framed_len = i32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert!(framed_len >= payload.len() && framed_len <= payload.len() + 3);
        assert_eq!(&frame[4..4 + payload.len()], &payload[..]);

        // последующие пакеты шифруются продолжением keystream
        let second = [7u8, 0, 0, 0, 1, 2, 3, 4];
        let mut dst2 = BytesMut::new();
        client.encode(Bytes::copy_from_slice(&second), &mut dst2).unwrap();
        let frame2 = server.receive(&dst2);
        let framed_len2 = i32::from_le_bytes(frame2[0..4].try_into().unwrap()) as usize;
        assert!(framed_len2 >= 8 && framed_len2 <= 11);
        assert_eq!(&frame2[4..12], &second);
    }

    #[test]
    fn roundtrip_server_to_client() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let server_payload: Vec<u8> = (0..25u32).flat_map(|i| i.to_le_bytes()).collect(); // 100 байт
        let wire = server.send(&framed(&server_payload));

        let mut seg = BytesMut::from(&wire[..]);
        let frame = client.decode(&mut seg).unwrap().unwrap();
        assert_eq!(frame.len(), 100);
        assert_eq!(&frame[..], &server_payload[..]);
    }

    #[test]
    fn head_sent_only_once() {
        let (mut client, _init) = test_codec();
        assert!(!client.head_sent());
        let mut dst = BytesMut::new();
        client.encode(Bytes::from_static(&[1, 2, 3, 4]), &mut dst).unwrap();
        assert!(client.head_sent());
        client.encode(Bytes::from_static(&[5, 6, 7, 8]), &mut dst).unwrap();
        assert!(client.head_sent());
    }

    #[test]
    fn decode_two_packets_at_once() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let mut all = Vec::new();
        for chunk in [vec![1u8; 64], vec![2u8; 36], vec![3u8; 12]] {
            all.extend_from_slice(&server.send(&framed(&chunk)));
        }

        let mut seg = BytesMut::from(&all[..]);
        let mut seen = Vec::new();
        while let Some(frame) = client.decode(&mut seg).unwrap() {
            seen.push(frame[0]);
        }
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn decode_missing_bytes_then_complete() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);

        let payload = vec![9u8; 48]; // длина кадра всегда кратна 4 (intermediate)
        let wire = server.send(&framed(&payload));
        let mut seg = BytesMut::from(&wire[..30]);
        assert!(client.decode(&mut seg).unwrap().is_none());
        // догоняем остаток — кадр собирается целиком
        seg.extend_from_slice(&wire[30..]);
        let frame = client.decode(&mut seg).unwrap().unwrap();
        assert_eq!(&frame[..], &payload[..]);
    }

    #[test]
    fn decode_bad_status_negative_len() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);
        let mut err_bytes = (-404i32).to_le_bytes().to_vec();
        err_bytes.extend_from_slice(&0i32.to_le_bytes());
        let wire = server.send(&err_bytes);
        let mut seg = BytesMut::from(&wire[..]);
        match client.decode(&mut seg) {
            Err(MtProxyError::BadStatus { status }) => assert_eq!(status, 404),
            other => panic!("ожидался BadStatus, получено: {other:?}"),
        }
    }

    #[test]
    fn decode_bad_status_len4() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);
        let mut err_bytes = (4i32).to_le_bytes().to_vec();
        err_bytes.extend_from_slice(&(-407i32).to_le_bytes());
        let wire = server.send(&err_bytes);
        let mut seg = BytesMut::from(&wire[..]);
        match client.decode(&mut seg) {
            Err(MtProxyError::BadStatus { status }) => assert_eq!(status, 407),
            other => panic!("ожидался BadStatus, получено: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_len_immediately() {
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);
        // только поле длины — превышение лимита отлавливаем без буферизации
        let wire = server.send(&(0x100000i32).to_le_bytes());
        let mut seg = BytesMut::from(&wire[..]);
        assert!(matches!(client.decode(&mut seg), Err(MtProxyError::BadLen { .. })));
    }

    #[test]
    fn decrypt_resumes_across_partial_reads() {
        // приход данных по 5 байт (как в реальном TCP) не ломает расшифровку
        let (mut client, init) = test_codec();
        let mut server = SimulatedServer::from_init(&init, &TEST_SECRET);
        let payload = vec![7u8; 100];
        let wire = server.send(&framed(&payload));
        let mut seg = BytesMut::new();
        let mut frames = Vec::new();
        for chunk in wire.chunks(5) {
            seg.extend_from_slice(chunk);
            while let Some(f) = client.decode(&mut seg).unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0][..], &payload[..]);
    }
}
