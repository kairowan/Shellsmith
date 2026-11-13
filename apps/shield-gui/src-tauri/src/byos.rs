use crate::cert_store::CertificateStoreState;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use shield_core::local_secret::{decrypt_secret, encrypt_secret, load_storage_key};

const PREFIX: &str = "byos_profile:";
const SELECTED: &str = "selected_byos_profile_id";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Profile {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub auth_mode: String,
    pub runtime_cert: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedProfile {
    pub profile: Profile,
    pub api_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileInput {
    pub id: Option<String>,
    pub name: String,
    pub endpoint: String,
    pub auth_mode: String,
    pub runtime_cert: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Profiles {
    profiles: Vec<Profile>,
    selected_id: Option<String>,
}

fn record_key(id: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "BYOS 配置标识无效")?;
    Ok(format!("{PREFIX}{id}"))
}

pub(crate) fn load(store: &CertificateStoreState, id: &str) -> Result<SavedProfile, String> {
    let value: Option<String> = store
        .open()?
        .query_row(
            "SELECT value FROM app_state WHERE key=?1",
            [record_key(id)?],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| "读取 BYOS 配置失败")?;
    let value = value.ok_or("未找到 BYOS 配置，请重新选择")?;
    let key = load_storage_key(&store.byos_key_path(), false)?;
    let saved: SavedProfile = serde_json::from_str(&decrypt_secret(&key, &value)?)
        .map_err(|_| "BYOS 配置损坏，请恢复备份")?;
    if saved.profile.id != id {
        return Err("BYOS 配置标识不匹配".into());
    }
    validate(&saved)?;
    Ok(saved)
}

fn validate(saved: &SavedProfile) -> Result<(), String> {
    let auth = saved.profile.auth_mode.parse().map_err(str::to_owned)?;
    shield_core::validate_byos_options(
        Some(&saved.profile.endpoint),
        Some(&saved.api_key),
        Some(auth),
    )
    .map_err(|e| e.to_string())?;
    if saved.profile.name.is_empty()
        || saved.profile.name.chars().count() > 80
        || saved.profile.name.chars().any(char::is_control)
    {
        return Err("配置名称应为 1～80 个字符，不能包含控制字符".into());
    }
    if saved
        .profile
        .runtime_cert
        .as_ref()
        .is_some_and(|v| v.len() != 64 || !v.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("最终签名证书必须为 64 位 SHA-256".into());
    }
    Ok(())
}

fn resolve_input(
    store: &CertificateStoreState,
    input: ProfileInput,
) -> Result<SavedProfile, String> {
    let old = input.id.as_deref().map(|id| load(store, id)).transpose()?;
    let endpoint = input.endpoint.trim().trim_end_matches('/').to_owned();
    if input.api_key.as_ref().is_none_or(String::is_empty)
        && old.as_ref().is_some_and(|v| {
            v.profile.endpoint != endpoint || v.profile.auth_mode != input.auth_mode
        })
    {
        return Err(
            "更换服务地址或授权方式时必须重新填写 API key，避免把旧凭据发送给其他服务".into(),
        );
    }
    let api_key = input
        .api_key
        .filter(|v| !v.is_empty())
        .or_else(|| old.map(|v| v.api_key))
        .ok_or("请填写构建 API key")?;
    let saved = SavedProfile {
        profile: Profile {
            id: input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name: input.name.trim().into(),
            endpoint,
            auth_mode: input.auth_mode,
            runtime_cert: input
                .runtime_cert
                .filter(|v| !v.trim().is_empty())
                .map(|v| shield_core::normalize_fingerprint(&v)),
        },
        api_key,
    };
    Ok(saved)
}

fn save(store: &CertificateStoreState, input: ProfileInput) -> Result<Profile, String> {
    let saved = resolve_input(store, input)?;
    validate(&saved)?;
    let mut conn = store.open()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "保存 BYOS 配置失败")?;
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM app_state WHERE key LIKE 'byos_profile:%'",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "读取 BYOS 配置失败")?;
    let key = load_storage_key(&store.byos_key_path(), count == 0)?;
    let json = serde_json::to_string(&saved).map_err(|_| "编码 BYOS 配置失败")?;
    tx.execute("INSERT INTO app_state(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![record_key(&saved.profile.id)?, encrypt_secret(&key, &json)?]).map_err(|_| "保存 BYOS 配置失败")?;
    set_selected(&tx, Some(&saved.profile.id))?;
    tx.commit().map_err(|_| "保存 BYOS 配置失败")?;
    Ok(saved.profile)
}

fn set_selected(conn: &Connection, id: Option<&str>) -> Result<(), String> {
    if let Some(id) = id {
        let updated = conn.execute(
            "INSERT INTO app_state(key,value) SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM app_state WHERE key=?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![SELECTED, id, record_key(id)?],
        ).map_err(|_| "保存 BYOS 选择失败")?;
        if updated == 0 {
            return Err("未找到 BYOS 配置，请重新选择".into());
        }
    } else {
        conn.execute("DELETE FROM app_state WHERE key=?1", [SELECTED])
            .map_err(|_| "保存 BYOS 选择失败")?;
    }
    Ok(())
}

fn list(store: &CertificateStoreState) -> Result<Profiles, String> {
    let conn = store.open()?;
    let selected_id = conn
        .query_row(
            "SELECT value FROM app_state WHERE key=?1",
            [SELECTED],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| "读取 BYOS 选择失败")?;
    let mut stmt = conn
        .prepare("SELECT key FROM app_state WHERE key LIKE 'byos_profile:%' ORDER BY key")
        .map_err(|_| "读取 BYOS 配置失败")?;
    let ids = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| "读取 BYOS 配置失败")?;
    let profiles = ids
        .map(|id| {
            load(
                store,
                id.map_err(|_| "读取 BYOS 配置失败")?
                    .trim_start_matches(PREFIX),
            )
            .map(|v| v.profile)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Profiles {
        profiles,
        selected_id,
    })
}

#[tauri::command]
pub(crate) fn list_byos_profiles(
    store: tauri::State<'_, CertificateStoreState>,
) -> Result<Profiles, String> {
    list(&store)
}

#[tauri::command]
pub(crate) fn select_byos_profile(
    store: tauri::State<'_, CertificateStoreState>,
    id: Option<String>,
) -> Result<(), String> {
    set_selected(&store.open()?, id.as_deref())
}

#[tauri::command]
pub(crate) fn save_byos_profile(
    store: tauri::State<'_, CertificateStoreState>,
    input: ProfileInput,
) -> Result<Profile, String> {
    save(&store, input)
}

#[tauri::command]
pub(crate) async fn test_byos_connection(
    store: tauri::State<'_, CertificateStoreState>,
    input: ProfileInput,
) -> Result<shield_core::ByosConnectionCheck, String> {
    let saved = resolve_input(&store, input)?;
    let auth = saved.profile.auth_mode.parse().map_err(str::to_owned)?;
    // 网络在阻塞线程执行；探测不保存草稿，也不注册 IKM。
    tauri::async_runtime::spawn_blocking(move || {
        shield_core::check_byos_connection(&saved.profile.endpoint, &saved.api_key, auth)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "连接测试任务失败，请重试".to_owned())?
}

#[tauri::command]
pub(crate) fn delete_byos_profile(
    store: tauri::State<'_, CertificateStoreState>,
    id: String,
) -> Result<(), String> {
    delete(&store, &id)
}

fn delete(store: &CertificateStoreState, id: &str) -> Result<(), String> {
    store
        .open()?
        .execute(
            "DELETE FROM app_state WHERE key=?1 OR (key=?2 AND value=?3)",
            params![record_key(id)?, SELECTED, id],
        )
        .map_err(|_| "删除 BYOS 配置失败")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_encrypt_secrets_retain_blank_keys_and_reject_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            CertificateStoreState::new(dir.path().join("shield.db"), dir.path().join("keystores"));
        store
            .open()
            .unwrap()
            .execute_batch("CREATE TABLE app_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let input = |id, api_key| ProfileInput {
            id,
            api_key,
            name: "国内发布".into(),
            endpoint: "https://keys.example/".into(),
            auth_mode: "device_approval".into(),
            runtime_cert: None,
        };
        let draft = resolve_input(&store, input(None, Some("private-build-token".into()))).unwrap();
        assert_eq!(draft.api_key, "private-build-token");
        assert!(!store.byos_key_path().exists());
        let count: i64 = store
            .open()
            .unwrap()
            .query_row("SELECT count(*) FROM app_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0); // 测试草稿不写入数据库或生成本地存储密钥。
        let profile = save(&store, input(None, Some("private-build-token".into()))).unwrap();
        assert_eq!(
            resolve_input(&store, input(Some(profile.id.clone()), None))
                .unwrap()
                .api_key,
            "private-build-token"
        );
        let raw: String = store
            .open()
            .unwrap()
            .query_row(
                "SELECT value FROM app_state WHERE key=?1",
                [record_key(&profile.id).unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(raw.starts_with("enc:v1:"));
        assert!(!raw.contains("private-build-token"));
        assert!(!serde_json::to_string(&profile)
            .unwrap()
            .contains("private-build-token"));
        save(&store, input(Some(profile.id.clone()), Some(String::new()))).unwrap();
        assert_eq!(
            load(&store, &profile.id).unwrap().api_key,
            "private-build-token"
        );
        let mut changed = input(Some(profile.id.clone()), None);
        changed.endpoint = "https://other.example".into();
        assert!(resolve_input(&store, changed).is_err());
        let mut changed = input(Some(profile.id.clone()), None);
        changed.auth_mode = "play_integrity".into();
        assert!(resolve_input(&store, changed).is_err());
        assert!(!raw.contains("keys.example"));
        std::fs::remove_file(store.byos_key_path()).unwrap();
        assert!(load(&store, &profile.id).is_err());
        assert!(save(&store, input(None, Some("new-token".into()))).is_err());
        assert!(!store.byos_key_path().exists());
    }

    #[test]
    fn 重启后恢复最近选择并保留离线选择() {
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            CertificateStoreState::new(dir.path().join("shield.db"), dir.path().join("keystores"))
        };
        let store = open();
        store
            .open()
            .unwrap()
            .execute_batch("CREATE TABLE app_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let input = |name: &str| ProfileInput {
            id: None,
            name: name.into(),
            endpoint: "https://keys.example".into(),
            auth_mode: "device_approval".into(),
            runtime_cert: None,
            api_key: Some("test-build-token".into()),
        };
        let first = save(&store, input("服务一")).unwrap();
        let second = save(&store, input("服务二")).unwrap();
        drop(store);

        let reopened = open();
        let saved = list(&reopened).unwrap();
        assert_eq!(saved.profiles.len(), 2);
        assert_eq!(saved.selected_id.as_deref(), Some(second.id.as_str()));
        assert!(!serde_json::to_string(&saved)
            .unwrap()
            .contains("test-build-token"));
        assert_eq!(
            load(&reopened, &second.id).unwrap().api_key,
            "test-build-token"
        );

        set_selected(&reopened.open().unwrap(), Some(&first.id)).unwrap();
        delete(&reopened, &second.id).unwrap();
        assert_eq!(
            list(&open()).unwrap().selected_id.as_deref(),
            Some(first.id.as_str())
        );
        set_selected(&reopened.open().unwrap(), None).unwrap();
        assert_eq!(list(&open()).unwrap().selected_id, None);
        set_selected(&reopened.open().unwrap(), Some(&first.id)).unwrap();
        delete(&reopened, &first.id).unwrap();
        assert_eq!(list(&open()).unwrap().selected_id, None);
        assert!(set_selected(&reopened.open().unwrap(), Some(&first.id)).is_err());
    }
}
