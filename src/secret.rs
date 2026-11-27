// ============================================================
// Разбор секрета MTProto-прокси — аналог normalize_secret из Telethon.
//
// Поддерживаемые форматы (как в t.me/... ссылках Telegram):
//   • 32 hex-символа — «голый» секрет (plain randomized mode);
//   • 34 hex-символа с префиксом dd — то же самое, префикс отбрасывается;
//   • 34 hex-символа с префиксом ee — FakeTLS-секрет: разбирается, но
//     ТРАНСПОРТ FakeTLS НЕ реализован (см. README);
//   • base64 (в том числе без дополнения «=»);
//   • доменная часть после секрета (domain fronting) отбрасывается —
//     клиенту она не нужна, первые 16 байт — сам секрет.
// ============================================================

use sha2::{Digest, Sha256};

/// Как записан секрет (для диагностики и подсказок).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Голый hex-секрет.
    Plain,
    /// Hex-секрет с префиксом dd (plain randomized mode).
    DdPrefixed,
    /// Hex-секрет с префиксом ee (FakeTLS — транспорт не реализован).
    EePrefixed,
    /// Base64.
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    Empty,
    TooShort(usize),
    Invalid(String),
    /// Переменная окружения не задана (from_env).
    Missing(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::Empty => write!(f, "секрет пуст"),
            SecretError::TooShort(n) => {
                write!(f, "секрет короче 16 байт (получено {n} байт)")
            }
            SecretError::Invalid(s) => write!(f, "некорректный секрет: {s}"),
            SecretError::Missing(v) => {
                write!(f, "переменная окружения {v} не задана")
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Нормализованный 16-байтовый секрет MTProto-прокси (+ опциональный домен).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtProxySecret {
    bytes: [u8; 16],
    kind: SecretKind,
    domain: Option<String>,
}

impl MtProxySecret {
    /// Разбор секрета из строки .env или из ссылки t.me/proxy?server=...&secret=...
    /// Аналог Telethon normalize_secret.
    ///
    /// Доменная часть (domain fronting) после hex-секрета отрезается и
    /// доступна через [`MtProxySecret::domain`] — для plain-транспорта она
    /// не используется (нужна только FakeTLS).
    pub fn parse(raw: &str) -> Result<Self, SecretError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SecretError::Empty);
        }

        let mut hex_str = raw.to_string();
        let mut kind = SecretKind::Plain;
        if raw.len() >= 34 && (raw.starts_with("ee") || raw.starts_with("dd")) {
            kind = if raw.starts_with("ee") {
                SecretKind::EePrefixed
            } else {
                SecretKind::DdPrefixed
            };
            hex_str = raw[2..].to_string();
        }

        // 1) hex целиком (без домена)
        let mut bytes = match hex_decode(hex_str.as_bytes()) {
            Ok(b) => Some(b),
            Err(_) => None,
        };
        // 2) hex-секрет + ASCII-домен после него (domain fronting)
        let mut domain: Option<String> = None;
        if bytes.is_none() && hex_str.len() > 32 {
            if let Ok(head) = hex_decode(&hex_str.as_bytes()[..32]) {
                let tail = &hex_str[32..];
                if tail.bytes().all(|b| (32..127).contains(&b)) {
                    bytes = Some(head);
                    domain = Some(tail.to_string());
                }
            }
        }
        // 3) base64 (Telethon дописывает '=' до кратности 4)
        let bytes = match bytes {
            Some(b) => b,
            None => {
                let mut padded = raw.to_string();
                padded.push_str(&"=".repeat((4 - raw.len() % 4) % 4));
                match base64_decode(padded.as_bytes()) {
                    Ok(b) => {
                        kind = SecretKind::Base64;
                        b
                    }
                    Err(_) => {
                        return Err(SecretError::Invalid(
                            "ожидался hex (32 символа) или base64".into(),
                        ))
                    }
                }
            }
        };

        if bytes.len() < 16 {
            return Err(SecretError::TooShort(bytes.len()));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes[..16]);
        Ok(Self { bytes: out, kind, domain })
    }

    /// Секрет из переменной окружения (например, `PROXY_SECRET` из .env).
    ///
    /// Сам крейт не читает .env-файлы (это библиотека, а не приложение):
    /// поднимите их в своём коде через `dotenvy::dotenv()` — как это делает
    /// бот-родитель — и крейт возьмёт значение из std::env.
    ///
    /// ```no_run
    /// use mtproto_client_rust::MtProxySecret;
    ///
    /// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// // dotenvy::dotenv()?; // в приложении, до этого вызова
    /// let secret = MtProxySecret::from_env("PROXY_SECRET")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_env(var: &str) -> Result<Self, SecretError> {
        match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Self::parse(&v),
            Ok(_) => Err(SecretError::Invalid(format!(
                "переменная {var} задана, но пустая"
            ))),
            Err(_) => Err(SecretError::Missing(var.to_string())),
        }
    }

    /// Нормализованный секрет (первые 16 байт).
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Формат, в котором секрет был записан.
    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    /// Доменная часть (domain fronting), если она была в секрете.
    /// Для plain-транспорта не используется; нужна только FakeTLS.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Секрет объявлен FakeTLS (ee-префикс)? Для таких прокси нужен
    /// транспорт FakeTLS, которого в крейте пока нет.
    pub fn is_fake_tls(&self) -> bool {
        self.kind == SecretKind::EePrefixed
    }

    /// Отпечаток секрета для логов: первые 4 байта sha256, сам секрет не светится.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        let d = hasher.finalize();
        d.iter().take(4).map(|b| format!("{b:02x}")).collect()
    }
}

// --- минимальные hex/base64 (без внешних крейтов, как в Telethon-порте) ---

pub(crate) fn hex_decode(s: &[u8]) -> Result<Vec<u8>, ()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let lower = s.to_ascii_lowercase();
    for pair in lower.chunks(2) {
        let hi = (HEX.iter().position(|c| *c == pair[0]).ok_or(())?) as u8;
        let lo = (HEX.iter().position(|c| *c == pair[1]).ok_or(())?) as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub(crate) fn base64_decode(s: &[u8]) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in s {
        if b == b'=' {
            break;
        }
        let v = TABLE.iter().position(|c| *c == b).ok_or(())? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_variants() {
        // 32 hex-символа
        let s = MtProxySecret::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(s.kind(), SecretKind::Plain);
        assert_eq!(s.as_bytes()[0], 0x01);

        // 34 hex-символа с dd-префиксом
        let s = MtProxySecret::parse("dd0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(s.kind(), SecretKind::DdPrefixed);
        assert!(!s.is_fake_tls());

        // ee-префикс помечается как FakeTLS
        let s = MtProxySecret::parse("ee0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(s.kind(), SecretKind::EePrefixed);
        assert!(s.is_fake_tls());

        // base64 (16 байт), без '=' и с '='
        assert!(MtProxySecret::parse("ERERERERERERERERERERER==").is_ok());
        assert!(MtProxySecret::parse("ERERERERERERERERERERER").is_ok());

        // мусор
        assert!(MtProxySecret::parse("не секрет").is_err());
        assert!(MtProxySecret::parse("").is_err());
        assert!(MtProxySecret::parse("  ").is_err());
    }

    #[test]
    fn domain_part_ignored() {
        // доменная часть после секрета отрезается: первые 16 байт — секрет
        let s = MtProxySecret::parse("0123456789abcdef0123456789abcdefexample.com").unwrap();
        assert_eq!(s.as_bytes()[0], 0x01);
        assert_eq!(s.as_bytes()[15], 0xef);
        assert_eq!(s.domain(), Some("example.com"));

        // ee + домен (типовая domain-fronting ссылка)
        let s = MtProxySecret::parse("ee0123456789abcdef0123456789abcdefcloudflare.com").unwrap();
        assert!(s.is_fake_tls());
        assert_eq!(s.domain(), Some("cloudflare.com"));

        // dd без домена
        let s = MtProxySecret::parse("dd0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(s.domain(), None);
    }

    #[test]
    fn fingerprint_stable_and_short() {
        let a = MtProxySecret::parse("0123456789abcdef0123456789abcdef").unwrap();
        let b = MtProxySecret::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 8);
    }

    #[test]
    fn from_env_variants() {
        // задана и валидна
        std::env::set_var("MTPROXY_TEST_SECRET", "0123456789abcdef0123456789abcdef");
        let s = MtProxySecret::from_env("MTPROXY_TEST_SECRET").unwrap();
        assert_eq!(s.as_bytes()[0], 0x01);

        // задана, но пустая
        std::env::set_var("MTPROXY_TEST_SECRET", "   ");
        assert!(matches!(
            MtProxySecret::from_env("MTPROXY_TEST_SECRET"),
            Err(SecretError::Invalid(_))
        ));

        // не задана
        std::env::remove_var("MTPROXY_TEST_SECRET");
        assert!(matches!(
            MtProxySecret::from_env("MTPROXY_TEST_SECRET"),
            Err(SecretError::Missing(_))
        ));
    }
}
