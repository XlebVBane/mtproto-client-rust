// ============================================================
// mtproto-client-rust — клиентский транспорт MTProto-прокси Telegram.
//
// 1:1 порт ConnectionTcpMTProxyRandomizedIntermediate из Telethon
// (telethon/network/connection/tcpmtproxy.py, v1.40) с Python на Rust.
// Именно через этот транспорт работал оригинальный Python-бот, и через
// этот же порт ходит боевой Rust-бот «Боярышник» (проверено на живом
// MTProto-прокси).
//
// Возможности:
//   • обфускация AES-256-CTR: ключи выводятся из init-пейлоада И секрета
//     прокси (MTProxyIO.init_header из Telethon);
//   • кадрирование «randomized intermediate»: 4 байта LE-длины +
//     данные + 0..3 байта случайного паддинга;
//   • в init-пейлоад встраиваются тег dd dd dd dd и id датацентра;
//   • разбор секретов: hex (с префиксами dd/ee), base64, доменная часть;
//   • два уровня API:
//       - tokio-util Codec (MtProxyCodec) — подключается к ЛЮБОМУ
//         AsyncRead+AsyncWrite через Framed;
//       - фича "grammers": MtProxyTransport, реализующий
//         grammers_mtproto::transport::Transport.
// ============================================================

mod codec;
mod init;
mod secret;
mod stream;

pub use codec::{MtProxyCodec, MtProxyError};
pub use init::generate_init;
pub use secret::{MtProxySecret, SecretError};
pub use stream::{connect, connect_env, connect_timeout, swap_codec, ConnectError, MtProxyStream};

#[cfg(feature = "grammers")]
pub mod grammers_transport;
