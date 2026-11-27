# MTProto Client Rust

Крейт `mtproto-client-rust` — клиентский транспорт для подключения
к Telegram **через MTProto-прокси** на Rust.
Порт `ConnectionTcpMTProxyRandomizedIntermediate` из
[Telethon](https://github.com/LonamiWebs/Telethon) v1.40 (Python, MIT).

Крейт делает ровно одно: обфускация AES-256-CTR, кадрирование
«randomized intermediate» и разбор секретов прокси. Это **не полный
MTProto-клиент**: авторизация, TL-сериализация и API-вызовы — задача
клиента поверх, например [grammers](https://github.com/LonamiWebs/grammers).

## Установка

```toml
[dependencies]
mtproto-client-rust = "0.1"
# если нужен мостик к grammers (см. ниже):
# mtproto-client-rust = { version = "0.1", features = ["grammers"] }
```

или `cargo add mtproto-client-rust`.

## Быстрый старт

```rust
use mtproto_client_rust::{connect, MtProxySecret};
use futures_util::SinkExt as _;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = MtProxySecret::parse("dd0123456789abcdef0123456789abcdef")?;
    let mut stream = connect("proxy.example.com", 443, &secret, 2).await?;

    // send() шифрует кадр и кладёт в сеть; первый кадр автоматически
    // несёт с собой 64-байтовый handshake.
    stream.send(bytes::Bytes::from_static(&[0u8; 4])).await?;

    // next() возвращает РАСШИФРОВАННЫЕ кадры сервера
    // (длина и паддинг уже сняты) — это payload'ы MTProto.
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(payload) => println!("кадр {} байт", payload.len()),
            Err(e) => { eprintln!("транспорт: {e}"); break; }
        }
    }
    Ok(())
}
```

Для примера нужны ещё крейты `bytes`, `futures-util` (feature `sink`)
и `tokio-stream`. `dc_id` — номер датацентра, через который прокси
маршрутизирует трафик (обычно `2`).

## Подключение из переменных окружения

```rust
let stream = mtproto_client_rust::connect_env(2).await?;
```

Читает `PROXY_HOST`, `PROXY_PORT`, `PROXY_SECRET`. Сам крейт .env-файлы
не читает — поднимите их в приложении (`dotenvy::dotenv().ok()`),
дальше обычное окружение процесса.

```dotenv
PROXY_HOST=127.0.0.1
PROXY_PORT=443
PROXY_SECRET=dd0123456789abcdef0123456789abcdef
```

Есть также `connect_timeout(...)` — то же с таймаутом на TCP-соединение.

## Кодек поверх своего соединения

`MtProxyCodec` реализует `tokio_util::codec::Encoder<Bytes>` / `Decoder`,
поэтому подходит к любому `AsyncRead + AsyncWrite` через `Framed`
(TLS-сокет, unix-сокет, туннель):

```rust
use mtproto_client_rust::{MtProxyCodec, MtProxySecret};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, Decoder as _};

let secret = MtProxySecret::parse(&std::env::var("PROXY_SECRET")?)?;
let tcp = TcpStream::connect("127.0.0.1:443").await?;
let framed = Framed::new(tcp, MtProxyCodec::new(&secret, 2));
```

## Использование с grammers

[grammers](https://github.com/LonamiWebs/grammers) — Rust-порт Telethon,
но его клиент подключается напрямую к адресам датацентров и MTProto-прокси
не поддерживает. С этим крейтом:

```toml
mtproto-client-rust = { version = "0.1", features = ["grammers"] }
```

```rust
use mtproto_client_rust::{MtProxySecret, grammers_transport::MtProxyTransport};

let secret = MtProxySecret::parse(&secret_raw)?;
let transport = MtProxyTransport::from_secret(&secret, 2);
// transport реализует grammers_mtproto::transport::Transport —
// его можно отдавать в grammers-mtsender вместо стандартного.
```

Важно: у стокового `grammers-mtsender` нужно поправить два места (примерно
15 строк, `cargo patch` по path-зависимости):

1. Адрес TCP-соединения: если задан MTProto-прокси — открывать сокет
   к `PROXY_HOST:PROXY_PORT` вместо адреса датацентра (`dc_id` при этом
   попадает в заголовок обфускации, прокси сам маршрутизирует трафик).
2. Поле `transport` в `ConnectionParams` сделать фабрикой, принимающей
   `dc_id` и возвращающей `MtProxyTransport` (в стоковой версии там
   фиксированный транспорт без привязки к датацентру).

Всё шифрование и кадрирование при этом берёт на себя этот крейт — патч
mtsender меняет только адрес сокета и способ создания транспорта.

## Секреты

Понимает те же форматы, что Telethon и ссылки
`t.me/proxy?server=…&port=…&secret=…`:

| Формат | Пример | Результат |
| --- | --- | --- |
| 32 hex-символа | `0123456789abcdef0123456789abcdef` | plain-секрет |
| 34 hex с `dd` | `dd0123…` | plain (префикс отброшен) |
| 34 hex с `ee` | `ee0123…` | FakeTLS — разбирается, транспорт не реализован (см. Ограничения) |
| base64 | `ERERERERERERERERERERER==` | plain-секрет |
| hex + домен | `ee0123…abcdefcloudflare.com` | секрет + домен через `secret.domain()` |

```rust
secret.as_bytes();     // &[u8; 16] — нормализованный секрет
secret.kind();         // Plain | DdPrefixed | EePrefixed | Base64
secret.domain();       // Option<&str> — доменная часть, если была
secret.is_fake_tls();  // ee-префикс?
secret.fingerprint();  // строка-отпечаток для логов (секрет не светится)
```

## Ошибки

- `MtProxyError` (кадры): `BadStatus { status }` — транспортная ошибка
  прокси (`404` — неверный секрет, `429` — flood), `BadLen`, `Io`.
- `SecretError` (`MtProxySecret::parse` / `from_env`): пустой, слишком
  короткий или некорректный секрет.
- `ConnectError` (`connect_env`): `MissingEnv`, `BadConfig`, `Io`.

## Ограничения

- **FakeTLS (`ee…`) не реализован**: секрет разбирается
  (`is_fake_tls()`, `domain()`), но для подключения нужен отдельный
  транспорт с эмуляцией TLS-записей (в Telethon это
  `ConnectionTcpMTProxyFakeTLS`). PR приветствуются.
- Это только транспорт: auth-ключ, TL и авторизацию делает клиент поверх
  (grammers и т.п.), `dc_id` выбирает вызывающий.

## Тесты

```bash
cargo test --all-features
```

Юнит-тесты кодека и секретов + интеграционный тест через реальный
TCP-loopback (клиент ↔ симулятор сервера с теми же выводами ключей,
что у настоящего MTProxy).

## English

Client-side transport for connecting to Telegram through an MTProto
proxy — a 1:1 port of Telethon's `ConnectionTcpMTProxyRandomizedIntermediate`
(AES-256-CTR obfuscation, randomized-intermediate framing, proxy secret
parsing). Transport layer only: pair it with a full MTProto client such as
[grammers](https://github.com/LonamiWebs/grammers). FakeTLS (`ee`) secrets
are parsed but the FakeTLS transport is not implemented.

## Лицензия

MIT. Портировано из [Telethon](https://github.com/LonamiWebs/Telethon) (MIT).
