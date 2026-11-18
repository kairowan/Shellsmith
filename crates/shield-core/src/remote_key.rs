//! BYOS 注册仅发生在构建机；错误不包含凭据、响应原文或密钥。
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{io::Read, time::Duration};

/// 授权策略由构建端显式选择并绑定服务端记录，不按地域推断或自动降级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByosAuth {
    DeviceApproval,
    PlayIntegrity,
}

impl ByosAuth {
    pub fn min_android_api(self) -> u32 {
        match self {
            Self::DeviceApproval => 24,
            Self::PlayIntegrity => 29,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceApproval => "device_approval",
            Self::PlayIntegrity => "play_integrity",
        }
    }

    pub(crate) fn resources(self) -> &'static str {
        match self {
            Self::DeviceApproval => "resources-byos.zip",
            Self::PlayIntegrity => "resources-byos-play.zip",
        }
    }
}

impl std::str::FromStr for ByosAuth {
    type Err = &'static str;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "device_approval" => Ok(Self::DeviceApproval),
            "play_integrity" => Ok(Self::PlayIntegrity),
            _ => Err("BYOS 授权方式必须为 device_approval 或 play_integrity"),
        }
    }
}

pub(crate) fn validate_endpoint(endpoint: &str) -> Result<()> {
    ensure!(
        endpoint.starts_with("https://")
            && endpoint.is_ascii()
            && endpoint.len() <= 2048
            && !endpoint
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"\\@?#".contains(&b)),
        "BYOS 地址无效"
    );
    let url = url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("BYOS 地址无效"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "BYOS 地址必须为 HTTPS，且不得包含凭据、查询或片段"
    );
    Ok(())
}

pub(crate) fn validate_token(token: &str) -> Result<()> {
    ensure!(
        !token.is_empty()
            && token.len() <= 256
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "BYOS token_id 必须为 1～256 位字母、数字、下划线或连字符"
    );
    Ok(())
}

pub fn validate_options(
    endpoint: Option<&str>,
    api_key: Option<&str>,
    auth: Option<ByosAuth>,
) -> Result<()> {
    match (endpoint, api_key, auth) {
        (None, None, None) => Ok(()),
        (Some(endpoint), Some(key), Some(_)) => {
            validate_endpoint(endpoint)?;
            ensure!(
                !key.is_empty() && key.len() <= 4096 && key.bytes().all(|b| b.is_ascii_graphic()),
                "BYOS 构建端认证凭据为空或无效"
            );
            Ok(())
        }
        _ => anyhow::bail!("必须同时配置 byos_endpoint、byos_api_key 和 byos_auth；Google Play 仅在显式选择 play_integrity 时使用"),
    }
}

/// 只读探测的结果只包含固定分类，不回传服务原文、地址或凭据。
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByosConnectionCheck {
    pub code: &'static str,
    pub elapsed_ms: u64,
    pub http_status: Option<u16>,
}

pub fn check_connection(
    endpoint: &str,
    api_key: &str,
    auth: ByosAuth,
) -> Result<ByosConnectionCheck> {
    validate_options(Some(endpoint), Some(api_key), Some(auth))?;
    Ok(probe_connection(
        &format!("{}/v1/keys/check", endpoint.trim_end_matches('/')),
        api_key,
        auth,
        ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(10))
            .build(),
    ))
}

fn probe_connection(
    url: &str,
    api_key: &str,
    auth: ByosAuth,
    agent: ureq::Agent,
) -> ByosConnectionCheck {
    use rand::RngCore;
    let started = std::time::Instant::now();
    let mut nonce = [0; 32];
    rand::rng().fill_bytes(&mut nonce);
    let request_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let mut result = ByosConnectionCheck {
        code: "network",
        elapsed_ms: 0,
        http_status: None,
    };
    let response = agent.post(url)
        .set("Authorization", &format!("Bearer {api_key}"))
        .send_json(serde_json::json!({"auth_mode": auth.as_str(), "fetch_protocol": 2, "request_id": request_id}));
    match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => {
            let status = response.status();
            result.http_status = Some(status);
            result.code = match status {
                200 | 503 => check_probe_response(response, auth, &request_id),
                300..=399 => "redirect",
                401 | 403 => "unauthorized",
                404 | 405 => "unsupported",
                408 | 504 => "timeout",
                429 => "rate_limited",
                500..=599 => "server_error",
                _ => "http_error",
            };
        }
        Err(ureq::Error::Transport(error)) => {
            result.code = if has_timeout_source(&error) {
                "timeout"
            } else if error.kind() == ureq::ErrorKind::Dns {
                "dns"
            // ureq 2 把 TLS 错误归为 ConnectionFailed；只识别其固定标签，不回传原文。
            } else if error.message() == Some("tls connection init failed") {
                "tls"
            } else if error.kind() == ureq::ErrorKind::ConnectionFailed {
                "connection"
            } else {
                "network"
            };
        }
    }
    result.elapsed_ms = started.elapsed().as_millis() as u64;
    result
}

fn has_timeout_source(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        }) {
            return true;
        }
        source = error.source();
    }
    false
}

fn check_probe_response(
    response: ureq::Response,
    auth: ByosAuth,
    request_id: &str,
) -> &'static str {
    let status = response.status();
    let mut bytes = Vec::new();
    if let Err(error) = response.into_reader().take(4097).read_to_end(&mut bytes) {
        return if has_timeout_source(&error) {
            "timeout"
        } else {
            "response_error"
        };
    }
    if bytes.len() > 4096 {
        return "response_too_large";
    }
    if status == 503 {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ServiceError {
            error: String,
        }
        // 只接受固定错误码；供应商响应、主密钥标识和内部异常都不返回界面。
        return match serde_json::from_slice::<ServiceError>(&bytes) {
            Ok(body) if body.error == "KEY_BACKEND_UNAVAILABLE" => "key_backend_unavailable",
            _ => "server_error",
        };
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        service: String,
        fetch_protocol: u32,
        auth_mode: String,
        request_id: String,
        authorized: bool,
    }
    // 结构体解析同时拒绝重复字段，普通首页或通用健康检查的 HTTP 200 不能算通过。
    let Ok(body) = serde_json::from_slice::<Response>(&bytes) else {
        return "invalid_response";
    };
    if body.service != "shellsmith-byos" || body.request_id != request_id {
        return "invalid_response";
    }
    if body.fetch_protocol != 2 || body.auth_mode != auth.as_str() {
        return "protocol_mismatch";
    }
    if !body.authorized {
        return "unauthorized";
    }
    "ok"
}

pub(crate) fn register_ikm(
    endpoint: &str,
    ikm: &[u8],
    api_key: &str,
    auth: ByosAuth,
) -> Result<String> {
    validate_options(Some(endpoint), Some(api_key), Some(auth))?;
    ensure!(ikm.len() == 32, "BYOS IKM 必须为 32 字节");
    register(
        &format!("{}/v1/keys/register", endpoint.trim_end_matches('/')),
        serde_json::json!({"ikm": STANDARD.encode(ikm), "auth_mode": auth.as_str(), "fetch_protocol": 2}),
        api_key,
        auth,
    )
}

pub(crate) fn register_resource_group(
    endpoint: &str,
    api_key: &str,
    build_id: &str,
    group: &str,
    key: &[u8; 32],
) -> Result<String> {
    let auth = ByosAuth::DeviceApproval;
    validate_options(Some(endpoint), Some(api_key), Some(auth))?;
    let token = register(
        &format!(
            "{}/v1/resource-keys/register",
            endpoint.trim_end_matches('/')
        ),
        serde_json::json!({"ikm": STANDARD.encode(key), "auth_mode": auth.as_str(), "fetch_protocol": 2,
                          "build_id": build_id, "resource_group": group}),
        api_key,
        auth,
    )?;
    ensure!(
        token.starts_with("r_") && token.len() == 66,
        "BYOS 资源组 token 与协议不匹配"
    );
    Ok(token)
}

pub(crate) fn register_ios_resource_group(
    endpoint: &str,
    api_key: &str,
    build_id: &str,
    group: &str,
    app_id: &str,
    environment: &str,
    key: &[u8; 32],
) -> Result<String> {
    let auth = ByosAuth::DeviceApproval;
    validate_options(Some(endpoint), Some(api_key), Some(auth))?;
    let token = register(
        &format!(
            "{}/v1/ios-resource-keys/register",
            endpoint.trim_end_matches('/')
        ),
        serde_json::json!({"ikm": STANDARD.encode(key), "app_id": app_id, "environment": environment,
                          "build_id": build_id, "resource_group": group}),
        api_key,
        auth,
    )?;
    ensure!(
        token.starts_with("i_") && token.len() == 66,
        "App Attest 资源组 token 与协议不匹配"
    );
    Ok(token)
}

fn register(url: &str, body: serde_json::Value, api_key: &str, auth: ByosAuth) -> Result<String> {
    // 禁止重定向，避免构建凭据和 IKM 被转发给其他地址。
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .build();
    let response = agent
        .post(url)
        .set("Authorization", &format!("Bearer {api_key}"))
        .send_json(body)
        .map_err(|_| anyhow::anyhow!("BYOS 注册失败：请检查 HTTPS 服务、网络和构建端认证"))?;
    ensure!(response.status() == 200, "BYOS 注册必须返回 HTTP 200");
    let mut body = Vec::new();
    response
        .into_reader()
        .take(4097)
        .read_to_end(&mut body)
        .map_err(|_| anyhow::anyhow!("BYOS 注册响应读取失败"))?;
    ensure!(body.len() <= 4096, "BYOS 注册响应过大");
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("BYOS 注册响应必须为 JSON"))?;
    ensure!(
        value.get("auth_mode").and_then(|v| v.as_str()) == Some(auth.as_str())
            && value.get("fetch_protocol").and_then(|v| v.as_u64()) == Some(2),
        "BYOS 服务未确认所选授权方式及加密响应协议，请更新服务端"
    );
    let token = value
        .get("token_id")
        .and_then(|v| v.as_str())
        .context("BYOS 响应缺少 token_id")?;
    validate_token(token)?;
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener};

    #[test]
    fn endpoint_and_credential_boundaries() {
        assert!(validate_options(None, None, None).is_ok());
        assert!(validate_options(
            Some("https://keys.example/api"),
            Some("test"),
            Some(ByosAuth::DeviceApproval)
        )
        .is_ok());
        for endpoint in [
            "http://keys.example",
            "https://user:secret@keys.example",
            "https://keys.example?a=b",
            "https://keys.example#secret",
            " https://keys.example",
            "https://keys.example\n",
        ] {
            assert!(validate_endpoint(endpoint).is_err());
        }
        assert!(validate_options(Some("https://keys.example"), None, None).is_err());
        assert!(validate_options(None, Some("secret"), None).is_err());
        for flags in 1..7 {
            assert!(validate_options(
                (flags & 1 != 0).then_some("https://keys.example"),
                (flags & 2 != 0).then_some("secret"),
                (flags & 4 != 0).then_some(ByosAuth::DeviceApproval)
            )
            .is_err());
        }
        for key in ["", "two words", "秘密", "test\n"] {
            assert!(validate_options(
                Some("https://keys.example"),
                Some(key),
                Some(ByosAuth::DeviceApproval)
            )
            .is_err());
        }
        for token in ["", "../key", "token\n", "令牌"] {
            assert!(validate_token(token).is_err());
        }
    }

    #[test]
    fn register_contract_and_failure_redaction() {
        for (status, response, ok) in [
            (
                "200 OK",
                r#"{"token_id":"test_123-4","auth_mode":"device_approval","fetch_protocol":2}"#,
                true,
            ),
            ("200 OK", r#"{"token_id":"valid"}"#, false),
            (
                "200 OK",
                r#"{"token_id":"valid","auth_mode":"play_integrity","fetch_protocol":2}"#,
                false,
            ),
            (
                "200 OK",
                r#"{"token_id":"valid","auth_mode":"device_approval","fetch_protocol":1}"#,
                false,
            ),
            (
                "200 OK",
                r#"{"token_id":"../secret","auth_mode":"device_approval","fetch_protocol":2}"#,
                false,
            ),
            ("302 Found", r#"{"token_id":"secret"}"#, false),
            ("403 Forbidden", "private-api-key", false),
        ] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let header = String::from_utf8(request).unwrap();
                assert!(header.starts_with("POST /v1/keys/register HTTP/1.1"));
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(header.contains("Authorization: Bearer private-api-key"));
                assert!(body.get("api_key").is_none());
                assert_eq!(body["auth_mode"], "device_approval");
                assert_eq!(body["fetch_protocol"], 2);
                assert_eq!(
                    STANDARD.decode(body["ikm"].as_str().unwrap()).unwrap(),
                    [42; 32]
                );
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: http://{address}/must-not-follow\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            });
            let result = register(
                &format!("http://{address}/v1/keys/register"),
                serde_json::json!({"ikm": STANDARD.encode([42; 32]), "auth_mode": "device_approval", "fetch_protocol": 2}),
                "private-api-key",
                ByosAuth::DeviceApproval,
            );
            assert_eq!(result.is_ok(), ok);
            if let Err(error) = result {
                assert!(!format!("{error:#}").contains("private-api-key"));
                if status.starts_with("302") {
                    assert!(error.to_string().contains("HTTP 200"));
                }
            }
            thread.join().unwrap();
        }
    }

    #[test]
    fn connection_probe_checks_identity_auth_protocol_limits_and_redacts() {
        for (case, status, expected) in [
            ("ok", 200, "ok"),
            ("unauthorized", 401, "unauthorized"),
            ("forbidden", 403, "unauthorized"),
            ("missing", 404, "unsupported"),
            ("method", 405, "unsupported"),
            ("redirect", 302, "redirect"),
            ("limited", 429, "rate_limited"),
            ("server", 503, "server_error"),
            ("backend", 503, "key_backend_unavailable"),
            ("backend_unknown", 503, "server_error"),
            ("backend_duplicate", 503, "server_error"),
            ("backend_extra", 503, "server_error"),
            ("backend_wrong_status", 200, "invalid_response"),
            ("status", 204, "http_error"),
            ("malformed", 200, "invalid_response"),
            ("nonce", 200, "invalid_response"),
            ("service", 200, "invalid_response"),
            ("mode", 200, "protocol_mismatch"),
            ("version", 200, "protocol_mismatch"),
            ("denied", 200, "unauthorized"),
            ("large", 200, "response_too_large"),
            ("duplicate", 200, "invalid_response"),
            ("slow", 200, "timeout"),
        ] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with("POST /customer/v1/keys/check HTTP/1.1"));
                assert!(header.contains("Authorization: Bearer private-probe-key"));
                let size: usize = header
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|s| s.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; size];
                stream.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.as_object().unwrap().len(), 3);
                assert_eq!(request["auth_mode"], "device_approval");
                assert_eq!(request["fetch_protocol"], 2);
                assert_eq!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(request["request_id"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    32
                );
                assert!(!String::from_utf8(body)
                    .unwrap()
                    .contains("private-probe-key"));
                let mut response = serde_json::json!({"service":"shellsmith-byos", "authorized":true, "auth_mode":"device_approval", "fetch_protocol":2, "request_id":request["request_id"]});
                match case {
                    "nonce" => response["request_id"] = "stale".into(),
                    "service" => response["service"] = "other".into(),
                    "mode" => response["auth_mode"] = "play_integrity".into(),
                    "version" => response["fetch_protocol"] = 1.into(),
                    "denied" => response["authorized"] = false.into(),
                    "slow" => std::thread::sleep(Duration::from_millis(200)),
                    _ => {}
                }
                let response = match case {
                    "backend" | "backend_wrong_status" => {
                        r#"{"error":"KEY_BACKEND_UNAVAILABLE"}"#.into()
                    }
                    "backend_unknown" => r#"{"error":"private-probe-key"}"#.into(),
                    "backend_duplicate" => {
                        r#"{"error":"KEY_BACKEND_UNAVAILABLE","error":"private-probe-key"}"#.into()
                    }
                    "backend_extra" => {
                        r#"{"error":"KEY_BACKEND_UNAVAILABLE","key_ref":"private-probe-key"}"#
                            .into()
                    }
                    "malformed" => "<html>private-probe-key</html>".into(),
                    "large" => "x".repeat(4097),
                    "duplicate" => response
                        .to_string()
                        .replacen('{', "{\"authorized\":false,", 1),
                    _ => response.to_string(),
                };
                let _ = write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLocation: http://{address}/must-not-follow\r\nConnection: close\r\n\r\n{response}", response.len());
            });
            let result = probe_connection(
                &format!("http://{address}/customer/v1/keys/check"),
                "private-probe-key",
                ByosAuth::DeviceApproval,
                ureq::AgentBuilder::new()
                    .redirects(0)
                    .timeout(if case == "slow" {
                        Duration::from_millis(50)
                    } else {
                        Duration::from_secs(2)
                    })
                    .build(),
            );
            assert_eq!(result.code, expected, "{case}");
            let report = serde_json::to_string(&result).unwrap();
            assert!(!report.contains("private-probe-key") && !report.contains("customer"));
            if case != "slow" {
                assert_eq!(result.http_status, Some(status));
            }
            thread.join().unwrap();
        }
        assert!(check_connection(
            "http://localhost",
            "private-probe-key",
            ByosAuth::DeviceApproval
        )
        .is_err());
    }

    #[test]
    #[ignore = "需要本机 OpenSSL 生成临时证书；不改变系统信任设置"]
    fn connection_probe_real_tls() {
        use std::sync::Arc;
        use ureq::rustls::{
            self,
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        let dir = tempfile::tempdir().unwrap();
        let openssl = |args: &[&str]| {
            let out = crate::utils::no_window_command("openssl")
                .current_dir(dir.path())
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "测试证书生成失败");
        };
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=BYOS-local-test-CA",
        ]);
        openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=localhost",
        ]);
        std::fs::write(dir.path().join("ext.cnf"), "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "ext.cnf",
            "-outform",
            "DER",
            "-out",
            "leaf.der",
        ]);
        openssl(&["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
        openssl(&[
            "pkcs8", "-topk8", "-nocrypt", "-in", "leaf.key", "-outform", "DER", "-out", "key.der",
        ]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        std::fs::read(dir.path().join("leaf.der")).unwrap(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        std::fs::read(dir.path().join("key.der")).unwrap(),
                    )),
                )
                .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                std::fs::read(dir.path().join("ca.der")).unwrap(),
            ))
            .unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        for (trusted, hostname, expected) in [
            (true, "localhost", "ok"),
            (false, "localhost", "tls"),
            (true, "127.0.0.1", "tls"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = server_config.clone();
            let thread = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(config).unwrap(),
                    socket,
                );
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        assert_ne!(expected, "ok");
                        assert!(header.is_empty());
                        return;
                    }
                    header.push(byte[0]);
                }
                assert_eq!(expected, "ok");
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with("POST /v1/keys/check HTTP/1.1"));
                let size: usize = header
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|s| s.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; size];
                stream.read_exact(&mut body).unwrap();
                let mut body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                body["service"] = "shellsmith-byos".into();
                body["authorized"] = true.into();
                let response = body.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )
                .unwrap();
                stream.flush().unwrap();
            });
            let agent = ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(3));
            let agent = if trusted {
                agent.tls_config(client_config.clone())
            } else {
                agent
            }
            .build();
            let result = probe_connection(
                &format!("https://{hostname}:{port}/v1/keys/check"),
                "test-only-key",
                ByosAuth::DeviceApproval,
                agent,
            );
            assert_eq!(result.code, expected);
            thread.join().unwrap();
        }
    }
}
