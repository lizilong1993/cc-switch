//! Claude Science（原生 Windows）接入：安装探测、隔离虚拟登录、经本地代理路由到第三方 provider。
//!
//! 设计要点：
//! - 只在 CSSwitch 私有的隔离目录里生成托管档案，绝不读写真实的用户级 .claude-science。
//! - 虚拟登录沿用 Science 0.1.x 的 v2 加密契约（HKDF-SHA256 + AES-256-GCM），
//!   与 Claude Desktop 的本地 gateway 路由复用同一套 provider 命名空间。

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// encryption.key 中必须齐备的四把密钥。
const KEY_NAMES: [&str; 4] = [
    "ANTHROPIC_API_KEY_ENCRYPTION_KEY",
    "OAUTH_ENCRYPTION_KEY",
    "JWT_SIGNING_SECRET",
    "USER_SECRET_ENCRYPTION_KEY",
];

/// 与 Science 二进制内的常量保持一致（不可改动，否则解不开）。
const HKDF_INFO: &[u8] = b"operon:aes-256-gcm:oauth";
const AAD: &[u8] = b"v2:oauth";
const MAGIC: &str = "v2:";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// CSSwitch 私有隔离目录名（位于 ~/.cc-switch 下）。
pub const PROFILE_DIR_NAME: &str = "claude-science-proxy";

/// 代理上供 Science 使用的路由前缀。
pub const ROUTE_PREFIX: &str = "/claude-science";

/// 虚拟账号邮箱：必须是 .invalid 保留域，确保永远不是真实账号。
pub const VIRTUAL_EMAIL: &str = "virtual@localhost.invalid";

/// 环境变量覆盖：指定 Science 可执行文件。
pub const BIN_ENV: &str = "CC_SWITCH_CLAUDE_SCIENCE_BIN";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceInstall {
    pub exe: PathBuf,
    pub version: Option<String>,
    pub real_data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceStatus {
    pub supported: bool,
    pub installed: bool,
    pub exe: Option<PathBuf>,
    pub version: Option<String>,
    pub profile_dir: Option<PathBuf>,
    pub has_virtual_login: bool,
    pub message: String,
}

// ---------- 路径 ----------

/// ~/.cc-switch 下的隔离根目录。
pub fn profile_root() -> Result<PathBuf, String> {
    let base = crate::config::get_app_config_dir();
    Ok(base.join(PROFILE_DIR_NAME))
}

/// 隔离 data-dir（= Science 的认证目录）。
pub fn isolated_data_dir() -> Result<PathBuf, String> {
    Ok(profile_root()?.join(".claude-science"))
}

fn home_dir() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "无法定位用户主目录".to_string())
}

/// 真实安装默认位置（仅用于探测与复用 conda/runtime，不作为写入目标）。
#[cfg(windows)]
fn default_install_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|base| base.join("Programs").join("ClaudeScience"))
}

#[cfg(not(windows))]
fn default_install_dir() -> Option<PathBuf> {
    None
}

fn install_json_version(dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(dir.join("install.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// 探测本机已安装的 Claude Science。
///
/// Windows 默认探测 %LOCALAPPDATA%\\Programs\\ClaudeScience；可用 BIN_ENV 覆盖。
pub fn detect_install() -> Result<ScienceInstall, String> {
    let explicit = std::env::var_os(BIN_ENV).map(PathBuf::from);
    let (exe, version) = match explicit {
        Some(path) => {
            if !path.is_file() {
                return Err(format!("{BIN_ENV} 指向的文件不存在：{}", path.display()));
            }
            let version = path.parent().and_then(install_json_version);
            (path, version)
        }
        None => {
            let dir = default_install_dir().ok_or_else(|| {
                "当前平台暂不支持原生 Claude Science 接入（当前仅实现 Windows）".to_string()
            })?;
            #[cfg(windows)]
            let exe_name = "claude-science.exe";
            #[cfg(not(windows))]
            let exe_name = "claude-science";
            let exe = dir.join(exe_name);
            if !exe.is_file() {
                return Err(format!(
                    "未找到 Claude Science：{}（可用 {BIN_ENV} 指定可执行文件）",
                    exe.display()
                ));
            }
            let version = install_json_version(&dir);
            (exe, version)
        }
    };
    Ok(ScienceInstall {
        exe,
        version,
        real_data_dir: home_dir().ok().map(|h| h.join(".claude-science")),
    })
}

pub fn status() -> ScienceStatus {
    let profile_dir = profile_root().ok();
    let has_virtual_login = profile_dir
        .as_ref()
        .map(|p| has_login(&p.join(".claude-science")))
        .unwrap_or(false);
    match detect_install() {
        Ok(install) => ScienceStatus {
            supported: true,
            installed: true,
            exe: Some(install.exe),
            version: install.version,
            profile_dir,
            has_virtual_login,
            message: String::new(),
        },
        Err(message) => ScienceStatus {
            supported: cfg!(windows),
            installed: false,
            exe: None,
            version: None,
            profile_dir,
            has_virtual_login,
            message,
        },
    }
}

// ---------- v2 令牌加解密 ----------

fn rand_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn derive_key(oauth_key_b64: &str) -> Result<[u8; 32], String> {
    let ikm = B64
        .decode(oauth_key_b64.trim())
        .map_err(|e| format!("OAUTH_ENCRYPTION_KEY 不是合法 base64：{e}"))?;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&[]), &ikm);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|_| "HKDF expand 失败".to_string())?;
    Ok(out)
}

/// 加密为 "v2:" + base64(IV ‖ 密文 ‖ tag)。
pub fn encrypt_token_v2(plaintext: &[u8], oauth_key_b64: &str) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let derived = derive_key(oauth_key_b64)?;
    let iv = rand_bytes(IV_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| "AES-256-GCM 加密失败".to_string())?;

    let mut framed = iv;
    framed.extend_from_slice(&ciphertext);
    Ok(format!("{MAGIC}{}", B64.encode(&framed)))
}

/// 解密 "v2:..."，校验 tag。
pub fn decrypt_token_v2(body: &str, oauth_key_b64: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let raw = B64
        .decode(
            body.strip_prefix(MAGIC)
                .ok_or_else(|| "缺少 v2: 前缀".to_string())?,
        )
        .map_err(|e| format!("v2 体不是合法 base64：{e}"))?;
    if raw.len() < IV_LEN + TAG_LEN {
        return Err("v2 密文过短".to_string());
    }
    let (iv, rest) = raw.split_at(IV_LEN);
    let derived = derive_key(oauth_key_b64)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: rest,
                aad: AAD,
            },
        )
        .map_err(|_| "AES-256-GCM 解密/验签失败".to_string())
}

// ---------- encryption.key ----------

fn parse_key_file(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(index) = line.find('=') {
            if index > 0 {
                let key = line[..index].trim();
                let value = line[index + 1..].trim();
                if !key.is_empty() && !value.is_empty() {
                    out.push((key.to_string(), value.to_string()));
                }
            }
        }
    }
    out
}

fn read_oauth_key(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("encryption.key")).ok()?;
    parse_key_file(&text)
        .into_iter()
        .find(|(k, _)| k == "OAUTH_ENCRYPTION_KEY")
        .map(|(_, v)| v)
        .filter(|v| B64.decode(v.trim()).map(|b| b.len() >= 16).unwrap_or(false))
}

/// 复用已存在的密钥（保证旧 .enc 仍可解），缺失的补齐后写回。
fn ensure_encryption_key(data_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("创建隔离目录失败：{e}"))?;
    let key_file = data_dir.join("encryption.key");

    let mut existing = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&key_file) {
        existing = parse_key_file(&text);
    }
    let oauth_usable = existing
        .iter()
        .find(|(k, _)| k == "OAUTH_ENCRYPTION_KEY")
        .map(|(_, v)| B64.decode(v.trim()).map(|b| b.len() >= 16).unwrap_or(false))
        .unwrap_or(false);
    if !oauth_usable {
        existing.retain(|(k, _)| k != "OAUTH_ENCRYPTION_KEY");
    }
    for name in KEY_NAMES {
        if !existing.iter().any(|(k, _)| k == name) {
            existing.push((name.to_string(), B64.encode(rand_bytes(32))));
        }
    }

    let mut blob = String::new();
    for name in KEY_NAMES {
        if let Some((_, value)) = existing.iter().find(|(k, _)| k == name) {
            blob.push_str(name);
            blob.push('=');
            blob.push_str(value);
            blob.push('\n');
        }
    }
    std::fs::write(&key_file, blob).map_err(|e| format!("写入 encryption.key 失败：{e}"))?;
    read_oauth_key(data_dir)
        .ok_or_else(|| "encryption.key 写入后仍读不到 OAUTH_ENCRYPTION_KEY".to_string())
}

// ---------- 虚拟登录 ----------

fn tokens_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(".oauth-tokens")
}

fn sanitize_user_id(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// 目录内是否已存在一个可解开的虚拟登录。
pub fn has_login(data_dir: &Path) -> bool {
    let dir = tokens_dir(data_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    let encs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "enc").unwrap_or(false))
        .collect();
    if encs.len() != 1 {
        return false;
    }
    let Some(key) = read_oauth_key(data_dir) else {
        return false;
    };
    match std::fs::read_to_string(&encs[0])
        .ok()
        .and_then(|body| decrypt_token_v2(&body, &key).ok())
        .and_then(|plain| serde_json::from_slice::<serde_json::Value>(&plain).ok())
    {
        Some(value) => value.get("provider").and_then(|v| v.as_str()) == Some("claude_ai"),
        None => false,
    }
}

/// 在隔离 data-dir 中写入一套虚拟登录（幂等）。
///
/// 返回 (account_uuid, org_uuid)。
pub fn write_virtual_login(data_dir: &Path) -> Result<(String, String), String> {
    // 护栏：写入目标必须位于 CSSwitch 私有隔离目录之下，绝不落到真实 Science 目录。
    let expected_root = profile_root()?;
    if !data_dir.starts_with(&expected_root) {
        return Err(format!(
            "拒绝写入：目标 {} 不在 CSSwitch 隔离目录 {} 之下",
            data_dir.display(),
            expected_root.display()
        ));
    }
    if let Ok(real) = home_dir().map(|h| h.join(".claude-science")) {
        if data_dir == real {
            return Err("拒绝写入：目标是真实 Claude Science 数据目录".to_string());
        }
    }

    let oauth_key = ensure_encryption_key(data_dir)?;

    let account_uuid = uuid::Uuid::new_v4().to_string();
    let org_uuid = uuid::Uuid::new_v4().to_string();
    let access = format!("sk-ant-virtual-{}", hex(&rand_bytes(24)));

    let blob = serde_json::json!({
        "access_token": access,
        "refresh_token": "",
        "api_key": null,
        "token_expires_at": "2099-01-01T00:00:00.000Z",
        "provider": "claude_ai",
        "scopes": "user:inference user:file_upload user:profile user:mcp_servers user:plugins",
        "email": VIRTUAL_EMAIL,
        "account_uuid": account_uuid,
        "subscription_type": "max",
        "rate_limit_tier": null,
        "seat_tier": null,
        "org_uuid": org_uuid,
        "billing_type": null,
        "has_extra_usage_enabled": false
    });
    let plaintext = serde_json::to_vec(&blob).map_err(|e| format!("序列化虚拟登录失败：{e}"))?;
    let body = encrypt_token_v2(&plaintext, &oauth_key)?;

    // Science 期望目录内恰好一个 .enc。
    let dir = tokens_dir(data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 .oauth-tokens 失败：{e}"))?;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|x| x == "enc").unwrap_or(false) {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("清理旧令牌 {} 失败：{e}", path.display()))?;
            }
        }
    }
    let user_id = sanitize_user_id(&account_uuid);
    if user_id.is_empty() {
        return Err("账号 ID 清洗后为空".to_string());
    }
    std::fs::write(dir.join(format!("{user_id}.enc")), body)
        .map_err(|e| format!("写入令牌失败：{e}"))?;

    if !has_login(data_dir) {
        return Err("虚拟登录自校验失败".to_string());
    }
    Ok((account_uuid, org_uuid))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 读取当前隔离目录里的虚拟身份 (account_uuid, org_uuid)。
///
/// 供代理侧的账号资料占位应答使用，确保与虚拟令牌里的声明一致。
pub fn virtual_identity() -> Option<(String, String)> {
    let data_dir = isolated_data_dir().ok()?;
    let key = read_oauth_key(&data_dir)?;
    let dir = tokens_dir(&data_dir);
    let encs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "enc").unwrap_or(false))
        .collect();
    if encs.len() != 1 {
        return None;
    }
    let body = std::fs::read_to_string(&encs[0]).ok()?;
    let plain = decrypt_token_v2(&body, &key).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&plain).ok()?;
    Some((
        value.get("account_uuid")?.as_str()?.to_string(),
        value.get("org_uuid")?.as_str()?.to_string(),
    ))
}

// ---------- 启动 / 停止 ----------

use std::process::{Child, Command};
use std::sync::Mutex;

use once_cell::sync::Lazy;

/// 当前被 CSSwitch 托管的 Science 子进程。
static SCIENCE_CHILD: Lazy<Mutex<Option<Child>>> = Lazy::new(|| Mutex::new(None));

/// 设为任意非空值可关闭 conda / runtime 的目录联接复用。
pub const NO_LINK_ENV: &str = "CC_SWITCH_CLAUDE_SCIENCE_NO_LINK";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchReport {
    pub pid: u32,
    pub port: u16,
    pub sandbox_port: u16,
    pub data_dir: PathBuf,
    pub base_url: String,
    pub linked: Vec<String>,
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("分配空闲端口失败：{e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("读取本地端口失败：{e}"))?
        .port();
    drop(listener);
    Ok(port)
}

/// 把真实安装里的重资产（conda / runtime / r-libs）以目录联接方式复用到隔离目录，
/// 避免隔离 data-dir 重新 provision 数 GB 内容。目标已存在则跳过。
#[cfg(windows)]
fn link_shared_assets(real: &Path, isolated: &Path) -> Result<Vec<String>, String> {
    use std::os::windows::process::CommandExt;

    let mut linked = Vec::new();
    for name in ["conda", "runtime", "r-libs"] {
        let source = real.join(name);
        let target = isolated.join(name);
        if !source.is_dir() || target.exists() {
            continue;
        }
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&target)
            .arg(&source)
            .creation_flags(0x0800_0000)
            .status()
            .map_err(|e| format!("创建目录联接失败：{e}"))?;
        if status.success() {
            linked.push(name.to_string());
        } else {
            log::warn!("[Claude Science] 复用 {name} 失败，将回退为独立 provisioning");
        }
    }
    Ok(linked)
}

#[cfg(not(windows))]
fn link_shared_assets(_real: &Path, _isolated: &Path) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

/// 在隔离目录里准备好托管档案与虚拟登录，并启动 Science。
///
/// proxy_base 形如 http://127.0.0.1:PORT，会自动拼上 ROUTE_PREFIX。
/// Science 只接受 https 或字面 loopback 的 http，调用方必须传 127.0.0.1。
pub fn launch(proxy_base: &str) -> Result<LaunchReport, String> {
    let install = detect_install()?;
    let home = profile_root()?;
    let data_dir = isolated_data_dir()?;
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("创建隔离 data-dir 失败：{e}"))?;

    let mut linked = Vec::new();
    if std::env::var_os(NO_LINK_ENV).is_none() {
        if let Some(real) = install.real_data_dir.as_deref() {
            linked = link_shared_assets(real, &data_dir)?;
        }
    }

    write_virtual_login(&data_dir)?;

    let port = free_port()?;
    let sandbox_port = port + 1;
    let base_url = format!("{}{}", proxy_base.trim_end_matches('/'), ROUTE_PREFIX);

    let mut command = Command::new(&install.exe);
    command
        .arg("serve")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--port")
        .arg(port.to_string())
        .arg("--sandbox-port")
        .arg(sandbox_port.to_string())
        .arg("--no-auto-update")
        .env("ANTHROPIC_BASE_URL", &base_url)
        // Science 的 auth_dir 由「用户主目录」推导，而不是 --data-dir；只传 data-dir
        // 会让它去读真实的 ~/.claude-science（登录态为空）。把 HOME / USERPROFILE 一起
        // 指向隔离根，两者才会重合（macOS 侧 CSSwitch 的做法同样是改写 HOME）。
        .env("HOME", &home)
        .env("USERPROFILE", &home);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP：不弹控制台，且便于整组终止。
        command.creation_flags(0x0800_0000 | 0x0000_0200);
    }

    let child = command
        .spawn()
        .map_err(|e| format!("启动 Claude Science 失败：{e}"))?;
    let pid = child.id();

    let mut guard = SCIENCE_CHILD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut previous) = guard.take() {
        let _ = previous.kill();
        let _ = previous.wait();
    }
    *guard = Some(child);
    drop(guard);

    log::info!(
        "[Claude Science] 已启动 pid={pid} port={port} base_url={base_url} 复用了 {:?}",
        linked
    );

    Ok(LaunchReport {
        pid,
        port,
        sandbox_port,
        data_dir,
        base_url,
        linked,
    })
}

/// 停止 CSSwitch 托管的 Science 实例，并回收本地子进程句柄。
pub fn stop() -> Result<String, String> {
    let install = detect_install()?;
    let data_dir = isolated_data_dir()?;

    let mut command = Command::new(&install.exe);
    command.arg("stop").arg("--data-dir").arg(&data_dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }

    let mut guard = SCIENCE_CHILD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(guard);

    match command.output() {
        Ok(output) => Ok(String::from_utf8_lossy(&output.stdout).trim().to_string()),
        Err(error) => Err(format!("调用 Claude Science stop 失败：{error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 JS 参考实现（Node crypto）逐字节对齐的 known-answer 向量。
    const KAT_KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KAT_DERIVED_HEX: &str =
        "f671f2f60ce427d6bcc1b8818b9db2ff05922fa6228d19e111d8f7c5f3a352d8";
    const KAT_ENC: &str = "v2:AAECAwQFBgcICQoLMax4a4J2W3VeVkulbQIkRGpFt5jDY9+3keajzsaUt3tONlpSheJHO3vpYrFsDK0YmHZABXJruA/7PUj4QXyLI9nlLD4c1dzENLXl2gb69iz3xbxnBjBihWiGiiAc3g4U4aDtoUSqC2tgkAjjkELUbb/9JLUCMbTeCQfyMfwRTCc6Zc/PcYrYdLIAxtO6fe3zwtBR6b1lstiG+PNPi9sH6VgDSAaRgZGdx4YRbWzfZOu7rEFtpDBXH2ZMITcGvgUMugE767wbXpFMR+jJp919xyyDRNqfKBZrYufbeg3n5wa5bNGjO+SI4cZ6ahR1b8dlhwpaHFWKzQd8qAgqvCW1jdMcZBT5UfrCMYHKprpBFB/cmxO/ws3aZHT7PmbGatS7EO7LcuByPswhOay4QAR/+mk46+8mf2ZQP8+9d6gku7gVMjhqVNW+ywDkh/V8obioMVrKMn0zRo+RKCyjUNMYWhT+AqKpQM/Gy9IUsghONQd8ktoxRdYRFbQNWmLVlihKq5048w2bT0YMQSEzi5w+7vmEg5FkSraOvN/KzcT1N6fvdGBa7h2en9+UFwu5ZexLcdIh+So+/Yv16u9KrlQSSWaddW1iX436GxCyFQJOetU37KmApuIyx+ajebvsu+mnSYnE+HIsFqc5CX2NiSyKvis4AZSWRi3vq5C+z20FZBDc4NF4fPk96TptXmAG1nZiXcCQX9c4Dp1jtsHGINgZyxc=";

    #[test]
    fn hkdf_matches_reference() {
        let derived = derive_key(KAT_KEY_B64).expect("derive");
        assert_eq!(hex(&derived), KAT_DERIVED_HEX);
    }

    #[test]
    fn decrypts_reference_ciphertext() {
        let plain = decrypt_token_v2(KAT_ENC, KAT_KEY_B64).expect("decrypt");
        let value: serde_json::Value = serde_json::from_slice(&plain).expect("json");
        assert_eq!(value["provider"], "claude_ai");
        assert_eq!(value["email"], VIRTUAL_EMAIL);
        assert_eq!(value["org_uuid"], "66666666-7777-4888-8999-aaaaaaaaaaaa");
    }

    #[test]
    fn roundtrip_preserves_payload() {
        let payload = br#"{"provider":"claude_ai","email":"virtual@localhost.invalid"}"#;
        let encoded = encrypt_token_v2(payload, KAT_KEY_B64).expect("encrypt");
        assert!(encoded.starts_with(MAGIC));
        let decoded = decrypt_token_v2(&encoded, KAT_KEY_B64).expect("decrypt");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        assert!(decrypt_token_v2("v2:AAAA", KAT_KEY_B64).is_err());
        assert!(decrypt_token_v2(KAT_ENC, "AAAA").is_err());
    }

    #[test]
    fn sanitize_user_id_keeps_only_safe_chars() {
        assert_eq!(sanitize_user_id("a1-b2_c3/d4"), "a1-b2_c3d4");
        assert_eq!(sanitize_user_id("///"), "");
    }
}
