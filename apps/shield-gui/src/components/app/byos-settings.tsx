import { useState } from "react";
import { AppButton, SelectInput, TextInput } from "@/components/app/common";
import { api, byosRequirements, type ByosProfiles, type ByosProfile, type ByosProfileInput, type ByosConnectionCheck } from "@/lib/tauri";
import type { Locale } from "@/lib/i18n";
import { notifyError } from "@/lib/notify";

export function ByosSettings({ value: { profiles, selectedId }, onChange, onSavingChange, locale, disabled }: {
  value: ByosProfiles;
  onChange: (value: ByosProfiles) => void;
  onSavingChange: (saving: boolean) => void;
  locale: Locale;
  disabled: boolean;
}) {
  const en = locale === "en";
  const value = profiles.find((profile) => profile.id === selectedId) ?? null;
  const [draft, setDraft] = useState<ByosProfileInput | null>(null);
  const [busy, setBusyState] = useState(false);
  const setBusy = (saving: boolean) => { setBusyState(saving); onSavingChange(saving); };
  const [testing, setTesting] = useState(false);
  const [check, setCheck] = useState<ByosConnectionCheck | null>(null);
  const [checkError, setCheckError] = useState("");
  const resetCheck = () => { setCheck(null); setCheckError(""); };
  const edit = (next: ByosProfileInput | null) => { resetCheck(); setDraft(next); };
  async function testConnection() {
    const input = draft ?? (value ? { ...value, apiKey: null } : null);
    if (!input) return;
    resetCheck(); setTesting(true);
    try { setCheck(await api.testByosConnection(input)); }
    catch (error) { setCheckError(String(error)); }
    finally { setTesting(false); }
  }
  async function select(id: string | null) {
    setBusy(true);
    edit(null);
    try { await api.selectByosProfile(id); onChange({ selectedId: id, profiles }); }
    catch (error) { notifyError(String(error)); }
    finally { setBusy(false); }
  }
  const change = (patch: Partial<ByosProfileInput>) => { resetCheck(); setDraft((previous) => previous ? { ...previous, ...patch } : previous); };
  async function save() {
    if (!draft) return;
    setBusy(true);
    try {
      const saved = await api.saveByosProfile(draft);
      const next = profiles.some((profile) => profile.id === saved.id)
        ? profiles.map((profile) => profile.id === saved.id ? saved : profile)
        : [...profiles, saved];
      onChange({ selectedId: saved.id, profiles: next });
      edit(null);
    } catch (error) { notifyError(String(error)); }
    finally { setBusy(false); }
  }
  async function remove() {
    if (!value || !window.confirm(en ? "Delete this local BYOS configuration? Published app keys are managed on your server." : "删除这套本地 BYOS 配置？已发布应用的密钥仍由你的服务端管理。")) return;
    setBusy(true);
    try { await api.deleteByosProfile(value.id); onChange({ selectedId: null, profiles: profiles.filter((profile) => profile.id !== value.id) }); edit(null); }
    catch (error) { notifyError(String(error)); }
    finally { setBusy(false); }
  }
  return <fieldset disabled={disabled || busy || testing} className="space-y-3 rounded-lg border p-3">
    <legend className="px-1 text-sm font-medium">{en ? "Key delivery" : "密钥交付"}</legend>
    <label className="block space-y-2 text-sm">
      <span>{en ? "Configuration" : "使用配置"}</span>
      <SelectInput value={selectedId ?? ""} onChange={(event) => void select(event.target.value || null)}>
        <option value="">{en ? "Offline · no server required" : "本地离线 · 无需服务器"}</option>
        {selectedId && !value && <option value={selectedId} disabled>{en ? "Saved service unavailable" : "已选服务不可用"}</option>}
        {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.authMode === "device_approval" ? (en ? "Device approval" : "设备授权") : "Google Play"}</option>)}
      </SelectInput>
    </label>
    <p className="text-xs text-muted-foreground">{value ? (en ? `${byosRequirements[value.authMode].platform}. Every app launch requires your HTTPS service. No automatic offline fallback.` : `${byosRequirements[value.authMode].platform}。应用每次启动需要访问你的 HTTPS 服务；授权失败不会自动改为离线。`) : (en ? "The default offline mode requires neither Google nor a key server." : "默认离线模式不需要 Google 配置，也不需要密钥服务器。")}</p>
    <div className="flex flex-wrap gap-2">
      <AppButton size="sm" variant="secondary" onClick={() => edit({ id: null, name: "", endpoint: "", authMode: "device_approval", runtimeCert: null, apiKey: "" })}>{en ? "Add service" : "新增服务"}</AppButton>
      {value && <><AppButton size="sm" variant="ghost" onClick={() => edit({ ...value, apiKey: null })}>{en ? "Edit" : "编辑"}</AppButton><AppButton size="sm" variant="ghost" onClick={() => void remove()}>{en ? "Delete" : "删除"}</AppButton></>}
    </div>
    {!draft && value && <AppButton size="sm" variant="secondary" onClick={() => void testConnection()}>{testing ? (en ? "Testing…" : "测试中…") : (en ? "Test connection" : "测试连接")}</AppButton>}
    {draft && <div className="space-y-3 border-t pt-3">
      <label className="block space-y-1 text-sm"><span>{en ? "Name" : "配置名称"}</span><TextInput value={draft.name} maxLength={80} onChange={(event) => change({ name: event.target.value })} /></label>
      <label className="block space-y-1 text-sm"><span>{en ? "Authorization" : "授权方式"}</span><SelectInput value={draft.authMode} onChange={(event) => change({ authMode: event.target.value as ByosProfile["authMode"] })}>
        <option value="device_approval">{en ? "Device approval · no Google dependency" : "服务端批准设备 · 无 Google 依赖"}</option><option value="play_integrity">Google Play Integrity</option>
      </SelectInput></label>
      <p className="text-xs text-muted-foreground">{draft.authMode === "device_approval" ? (en ? "Android 7.0+ (minSdkVersion 24). Approve devices in your service. Existing accounts or licenses can grant that approval." : "Android 7.0+（minSdkVersion 24）。在你的服务端批准设备；也可以由现有账号或许可证系统完成批准。") : (en ? "Android 10+ (minSdkVersion 29). Only this mode requires Play Console, Google service credentials and Play distribution. Keep Google secrets on the server." : "Android 10+（minSdkVersion 29）。仅此方式需要 Play Console、Google 服务身份及 Play 分发环境。Google 秘密只保存在服务端。")}</p>
      <label className="block space-y-1 text-sm"><span>HTTPS {en ? "service URL" : "服务地址"}</span><TextInput type="url" value={draft.endpoint} placeholder="https://keys.example.com/shellsmith" onChange={(event) => change({ endpoint: event.target.value })} /></label>
      <p className="text-xs text-muted-foreground">{en ? "Configure your master key or KMS/HSM in your HTTPS service. Keep master keys and provider credentials on the server; this form only needs the build API key." : "自有主密钥或 KMS/HSM 在你的 HTTPS 服务端配置。主密钥和厂商凭据留在服务端；这里仅填写构建 API key。"}</p>
      <label className="block space-y-1 text-sm"><span>{en ? "Build API key" : "构建 API key"}</span><TextInput type="password" autoComplete="new-password" value={draft.apiKey ?? ""} placeholder={draft.id ? (en ? "Leave empty to retain the saved key" : "留空保留已保存凭据") : ""} onChange={(event) => change({ apiKey: event.target.value })} /></label>
      <p className="text-xs text-muted-foreground">{en ? "Encrypted locally. The saved secret is never returned to this form or embedded in the APK." : "本地加密保存；已保存的秘密不会返回表单，也不会写入 APK。"}</p>
      <label className="block space-y-1 text-sm"><span>{en ? "Final signing certificate SHA-256 (optional)" : "最终签名证书 SHA-256（可选）"}</span><TextInput value={draft.runtimeCert ?? ""} onChange={(event) => change({ runtimeCert: event.target.value || null })} /></label>
      <p className="text-xs text-muted-foreground">{en ? "Leave empty to bind the input APK certificate. For Play App Signing, use the final app certificate, not the upload certificate." : "留空绑定输入 APK 的证书。Play 重签时填写最终应用签名证书，不是上传证书。"}</p>
      <div className="flex flex-wrap gap-2"><AppButton size="sm" variant="secondary" disabled={!draft.endpoint.trim() || (!draft.id && !draft.apiKey)} onClick={() => void testConnection()}>{testing ? (en ? "Testing…" : "测试中…") : (en ? "Test connection" : "测试连接")}</AppButton><AppButton size="sm" disabled={!draft.name.trim() || !draft.endpoint.trim() || (!draft.id && !draft.apiKey)} onClick={() => void save()}>{busy ? (en ? "Saving…" : "保存中…") : (en ? "Save and use" : "保存并使用")}</AppButton><AppButton size="sm" variant="ghost" onClick={() => edit(null)}>{en ? "Cancel" : "取消"}</AppButton></div>
    </div>}
    {(value || draft) && <p className="text-xs text-muted-foreground">{en ? "Testing sends the build credential to this HTTPS service, without saving this draft or registering a key. The server must implement /v1/keys/check. It does not verify device approval or app startup." : "测试会向所填 HTTPS 服务发送构建凭据，不保存草稿、不注册密钥。服务需实现 /v1/keys/check；测试不代表设备批准、最终签名或手机启动验证通过。"}</p>}
    <div role="status" aria-live="polite" aria-atomic="true" className="text-sm">
      {testing && <p>{en ? "Checking HTTPS, credentials and protocol (10-second request timeout; system DNS may take longer)…" : "正在检查 HTTPS、构建凭据及协议（请求超时 10 秒；系统域名解析可能额外等待）…"}</p>}
      {checkError && <p className="text-destructive">{checkError}</p>}
      {check && <div className="space-y-2 rounded-md border p-3">
        <p className={check.code === "ok" ? "text-foreground" : "text-destructive"}>{connectionMessage(check.code, en)}</p>
        <p className="text-xs text-muted-foreground">{check.elapsedMs} ms{check.httpStatus !== null && ` · HTTP ${check.httpStatus}`}</p>
        <ul className="space-y-1 text-xs">
          <li>HTTPS: {check.httpStatus !== null ? (en ? "Connected" : "已连接") : (en ? "Not confirmed" : "未确认")}</li>
          <li>{en ? "Credential authorization" : "构建凭据授权"}: {check.code === "ok" ? (en ? "Passed" : "通过") : check.code === "unauthorized" ? (en ? "Rejected" : "拒绝") : (en ? "Not confirmed" : "未确认")}</li>
          <li>{en ? "Selected mode / protocol" : "所选授权方式 / 协议"}: {check.code === "ok" ? (en ? "Passed" : "通过") : (en ? "Not confirmed" : "未通过验证")}</li>
        </ul>
      </div>}
    </div>
  </fieldset>;
}


function connectionMessage(code: string, en: boolean) {
  const messages: Record<string, [string, string]> = {
    ok: ["连接、构建凭据和协议检查通过", "Connection, credential and protocol checks passed"],
    dns: ["域名解析失败，请检查服务地址和 DNS", "DNS lookup failed; check the service address and DNS"],
    tls: ["TLS 握手或证书校验失败，请检查证书链、有效期及域名", "TLS handshake or certificate validation failed; check the certificate chain, validity and hostname"],
    connection: ["无法连接服务，请检查端口、防火墙及服务是否启动", "Connection failed; check the port, firewall and service"],
    network: ["网络请求失败，请检查网络或代理后重试", "Network request failed; check the network or proxy"],
    timeout: ["连接或响应超时，请检查服务负载和网络", "Connection or response timed out; check server load and network"],
    redirect: ["服务返回跳转，已拒绝转发凭据；请填写最终 HTTPS 地址", "Redirect refused to avoid forwarding credentials; use the final HTTPS URL"],
    unauthorized: ["构建凭据或所选授权方式被拒绝，请核对服务端策略", "Credential or authorization mode rejected; check the server policy"],
    unsupported: ["服务未实现检查接口，请按接入文档实现 POST /v1/keys/check", "Check endpoint unavailable; implement POST /v1/keys/check as documented"],
    rate_limited: ["服务请求过于频繁，请稍后重试", "Rate limited; retry later"],
    server_error: ["服务端错误，请检查密钥服务运行状态", "Server error; check the key service"],
    key_backend_unavailable: ["HTTPS 服务已响应，但密钥后端未就绪；请检查服务端主密钥、KMS/HSM 权限及连接", "HTTPS responded, but the key backend is unavailable; check the server master key, KMS/HSM permissions and connection"],
    http_error: ["服务返回非预期状态，请核对地址及接口配置", "Unexpected HTTP status; check URL and endpoint configuration"],
    response_error: ["响应读取失败或不完整，请检查服务及网络", "Incomplete response; check the service and network"],
    response_too_large: ["检查响应超过 4 KiB，请按协议缩减响应", "Check response exceeds 4 KiB; follow the response contract"],
    invalid_response: ["响应格式或请求标识不匹配，不能确认服务兼容", "Invalid response or request identity; service compatibility not confirmed"],
    protocol_mismatch: ["服务不支持所选授权方式或取钥协议 2，请更新服务配置", "Authorization mode or fetch protocol 2 mismatch; update the service"],
  };
  return (messages[code] ?? messages.network)[en ? 1 : 0];
}
