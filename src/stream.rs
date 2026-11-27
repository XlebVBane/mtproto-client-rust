// ============================================================
// Удобное подключение: TCP до прокси + MtProxyCodec поверх него.
// ============================================================

use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::codec::MtProxyCodec;
use crate::secret::MtProxySecret;

/// Поток MTProto-прокси: Stream<Item=Result<Bytes, MtProxyError>> +
/// Sink<Bytes> поверх TCP. Кадры — расшифрованные payload'ы MTProto
/// (длина и паддинг уже сняты, init отправлен кодеком автоматически).
pub type MtProxyStream = Framed<TcpStream, MtProxyCodec>;

/// Подключение к MTProto-прокси: TCP до `host:port`, затем кодек с
/// обфускацией под `secret` и маршрутизацией через датацентр `dc_id`.
///
/// ```no_run
/// use mtproto_client_rust::{connect, MtProxySecret};
///
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// let secret = MtProxySecret::parse("0123456789abcdef0123456789abcdef")?;
/// let mut stream = connect("127.0.0.1", 443, &secret, 2).await?;
/// // stream.send(bytes) / stream.next() — уже расшифрованные кадры
/// # Ok(())
/// # }
/// ```
pub async fn connect(
    host: &str,
    port: u16,
    secret: &MtProxySecret,
    dc_id: i32,
) -> std::io::Result<MtProxyStream> {
    let tcp = TcpStream::connect((host, port)).await?;
    Ok(Framed::new(tcp, MtProxyCodec::new(secret, dc_id)))
}

/// Подключение с таймаутом на установление TCP-соединения
/// (обфускационный handshake кодека не требует ожидания — он уходит
/// вместе с первым кадром, как в Telethon).
pub async fn connect_timeout(
    host: &str,
    port: u16,
    secret: &MtProxySecret,
    dc_id: i32,
    timeout: std::time::Duration,
) -> Result<MtProxyStream, std::io::Error> {
    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timeout"))??;
    Ok(Framed::new(tcp, MtProxyCodec::new(secret, dc_id)))
}

/// Подмена кодека в уже созданном Framed (например, чтобы переиспользовать
/// сокет с уже настроенными опциями TCP или сбросить состояние обфускации).
pub fn swap_codec(framed: MtProxyStream, codec: MtProxyCodec) -> MtProxyStream {
    let mut parts = framed.into_parts();
    parts.codec = codec;
    Framed::from_parts(parts)
}

/// Ошибка подключения из окружения ([`connect_env`]).
#[derive(Debug)]
pub enum ConnectError {
    /// Переменная окружения не задана.
    MissingEnv(String),
    /// Секрет/порт в переменных некорректны.
    BadConfig(String),
    /// Ошибка TCP-подключения к прокси.
    Io(std::io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::MissingEnv(v) => write!(f, "переменная окружения {v} не задана"),
            ConnectError::BadConfig(s) => write!(f, "некорректная настройка прокси: {s}"),
            ConnectError::Io(e) => write!(f, "ошибка подключения: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Подключение к MTProto-прокси целиком из переменных окружения:
/// `PROXY_HOST`, `PROXY_PORT`, `PROXY_SECRET` (имена — как в .env бота-родителя).
///
/// Сам крейт .env-файлы не читает: поднимите их в приложении
/// (`dotenvy::dotenv()`), дальше — нативное окружение процесса.
///
/// ```no_run
/// use mtproto_client_rust::connect_env;
///
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// // .env: PROXY_HOST=127.0.0.1, PROXY_PORT=443, PROXY_SECRET=dd0123...
/// // dotenvy::dotenv()?;
/// let stream = connect_env(2).await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect_env(dc_id: i32) -> Result<MtProxyStream, ConnectError> {
    let env_nonempty = |name: &str| -> Result<String, ConnectError> {
        match std::env::var(name) {
            Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
            Ok(_) => Err(ConnectError::BadConfig(format!(
                "переменная {name} задана, но пустая"
            ))),
            Err(_) => Err(ConnectError::MissingEnv(name.to_string())),
        }
    };
    let host = env_nonempty("PROXY_HOST")?;
    let port_raw = env_nonempty("PROXY_PORT")?;
    let port: u16 = port_raw
        .parse()
        .map_err(|_| ConnectError::BadConfig(format!("PROXY_PORT={port_raw} — не число")))?;
    let secret = MtProxySecret::from_env("PROXY_SECRET").map_err(|e| match e {
        crate::secret::SecretError::Missing(v) => ConnectError::MissingEnv(v),
        other => ConnectError::BadConfig(other.to_string()),
    })?;
    connect(&host, port, &secret, dc_id).await.map_err(ConnectError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Один последовательный тест: env — процесс-глобальная штука,
    /// чтобы не гонять с параллельными тестами.
    #[tokio::test]
    async fn connect_env_paths() {
        // 1) переменных нет → MissingEnv
        std::env::remove_var("PROXY_HOST");
        std::env::remove_var("PROXY_PORT");
        std::env::remove_var("PROXY_SECRET");
        match connect_env(2).await {
            Err(ConnectError::MissingEnv(v)) => assert_eq!(v, "PROXY_HOST"),
            other => panic!("ожидали MissingEnv, получили {other:?}"),
        }

        // 2) секрет-мусор → BadConfig ещё до сети
        std::env::set_var("PROXY_HOST", "127.0.0.1");
        std::env::set_var("PROXY_PORT", "443");
        std::env::set_var("PROXY_SECRET", "не секрет");
        assert!(matches!(connect_env(2).await, Err(ConnectError::BadConfig(_))));

        // 3) порт не число → BadConfig
        std::env::set_var("PROXY_SECRET", "0123456789abcdef0123456789abcdef");
        std::env::set_var("PROXY_PORT", "столько");
        assert!(matches!(connect_env(2).await, Err(ConnectError::BadConfig(_))));

        // 4) всё валидно, но адрес закрыт → Io (env прочитан, дошло до TCP)
        std::env::set_var("PROXY_PORT", "1"); // порт 1 на 127.0.0.1 обычно закрыт
        match connect_env(2).await {
            Err(ConnectError::Io(e)) => {
                assert_ne!(e.kind(), std::io::ErrorKind::Other);
            }
            other => panic!("ожидали Io, получили {other:?}"),
        }

        // уборка, чтобы не влиять на другие тесты
        std::env::remove_var("PROXY_HOST");
        std::env::remove_var("PROXY_PORT");
        std::env::remove_var("PROXY_SECRET");
    }
}
