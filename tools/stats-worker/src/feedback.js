// 软件内问题反馈接口：校验固定字段协议，为客户端生成的 Markdown 正文补幂等隐藏标记，
// 并用服务端持有的 GITHUB_TOKEN 直接创建 GitHub issue。
// 这里不导入 index.js，避免形成循环依赖；内部 json() 与 index.js 的响应头约定保持一致。

const encoder = new TextEncoder();

// 请求体字段集合完全固定，多一个或少一个都视为无效。
export const FEEDBACK_FIELDS = ["schema_version", "kind", "title", "body", "app_version"];

export const MAX_FEEDBACK_BYTES = 32768;
export const MAX_FEEDBACK_BODY_LENGTH = 24000;
export const MAX_FEEDBACK_TITLE_LENGTH = 120;
export const FEEDBACK_MARKER = "<!-- shellsmith-feedback:v1 -->";
export const FEEDBACK_ISSUE_ENDPOINT = "https://api.github.com/repos/kairowan/Shellsmith/issues";
export const FEEDBACK_UNAVAILABLE_ERROR = "反馈服务暂时不可用";
export const FEEDBACK_RATE_LIMITED_ERROR = "提交过于频繁，请稍后再试";
// 同一指纹 10 分钟内最多 1 次，一天最多 20 次。
export const FEEDBACK_WINDOW_LIMIT = 1;
export const FEEDBACK_DAILY_LIMIT = 20;

const KINDS = new Set(["bug", "feature"]);

const SEMVER_IDENTIFIER = "(?:0|[1-9]\\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)";
const SEMVER_BUILD = "[0-9A-Za-z-]+";
const APP_VERSION_PATTERN = new RegExp(
  `^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-${SEMVER_IDENTIFIER}(?:\\.${SEMVER_IDENTIFIER})*)?(?:\\+${SEMVER_BUILD}(?:\\.${SEMVER_BUILD})*)?$`,
);

// 标题与正文按 Unicode 码点计数，与客户端 chars().count() 的口径一致。
// 直接用 JS 的 .length 是 UTF-16 码元数，含 emoji 时会在客户端通过、却在服务端被拒。
function codePointLength(value) {
  return [...value].length;
}

function requiredText(value, maxLength, message) {
  if (typeof value !== "string" || codePointLength(value) < 1 || codePointLength(value) > maxLength) {
    throw new Error(message);
  }
  return value;
}

function validAppVersion(value) {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= 64
    && APP_VERSION_PATTERN.test(value);
}
// 校验固定字段协议；byteLength 为原始请求体字节数。
export function normalizeFeedback(value, byteLength) {
  if (byteLength !== undefined && byteLength > MAX_FEEDBACK_BYTES) throw new Error("反馈内容超过32768字节");
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("反馈格式无效");
  const keys = Object.keys(value);
  if (keys.length !== FEEDBACK_FIELDS.length || keys.some((key) => !FEEDBACK_FIELDS.includes(key))) {
    throw new Error("反馈字段无效");
  }
  if (value.schema_version !== 1) throw new Error("协议版本无效");
  if (!KINDS.has(value.kind)) throw new Error("反馈类型无效");
  requiredText(value.title, MAX_FEEDBACK_TITLE_LENGTH, "标题为空或过长");
  requiredText(value.body, MAX_FEEDBACK_BODY_LENGTH, "反馈正文为空或过长");
  if (!validAppVersion(value.app_version)) throw new Error("应用版本无效");

  const feedback = Object.fromEntries(FEEDBACK_FIELDS.map((field) => [field, value[field]]));
  if (encoder.encode(JSON.stringify(feedback)).byteLength > MAX_FEEDBACK_BYTES) {
    throw new Error("反馈内容超过32768字节");
  }
  return feedback;
}

// 正文幂等加隐藏标记：客户端已带标记时不重复添加，也不追加任何其它内容。
export function ensureFeedbackMarker(body) {
  return body.startsWith(FEEDBACK_MARKER) ? body : `${FEEDBACK_MARKER}\n${body}`;
}

// issue 标题前缀由服务端统一补齐，保证新旧客户端一致。
export function buildFeedbackIssue(feedback) {
  const isBug = feedback.kind === "bug";
  return {
    title: `[${isBug ? "Bug" : "功能建议"}] ${feedback.title}`,
    labels: isBug ? ["bug"] : ["enhancement"],
    body: ensureFeedbackMarker(feedback.body),
  };
}

// 计算 10 分钟限流窗口与当天起点，均使用 UTC 文本，便于 D1 直接比较。
export function fingerprintWindow(now = new Date()) {
  const time = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(time.getTime())) throw new Error("时间无效");
  const iso = time.toISOString();
  const day = iso.slice(0, 10);
  const hour = iso.slice(11, 13);
  const minute = Number(iso.slice(14, 16));
  const windowMinute = String(Math.floor(minute / 10) * 10).padStart(2, "0");
  return { windowStart: `${day}T${hour}:${windowMinute}`, dayStart: `${day}T00:00` };
}

// 纯函数限流判定：先看 10 分钟窗口，再看当天累计。
export function decideThrottle(windowCount, dayCount) {
  if (Number(windowCount) >= FEEDBACK_WINDOW_LIMIT) return { allowed: false, reason: "window" };
  if (Number(dayCount) >= FEEDBACK_DAILY_LIMIT) return { allowed: false, reason: "day" };
  return { allowed: true, reason: null };
}

// 指纹只保存 sha256 摘要，不落库原始 IP。
export async function fingerprintSource(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(String(value ?? "unknown")));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "content-type",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

// best-effort 限流：D1 未迁移或异常时只跳过限流，不阻断反馈提交。
async function checkThrottle(request, env, now) {
  if (!env.DB) return null;
  try {
    const fingerprint = await fingerprintSource(request.headers.get("CF-Connecting-IP"));
    const { windowStart, dayStart } = fingerprintWindow(now);
    const windowRow = await env.DB.prepare(
      "SELECT count FROM feedback_rate_limit WHERE fingerprint = ? AND window_start = ?",
    ).bind(fingerprint, windowStart).first();
    const dayRow = await env.DB.prepare(
      "SELECT COALESCE(SUM(count), 0) AS total FROM feedback_rate_limit WHERE fingerprint = ? AND window_start >= ?",
    ).bind(fingerprint, dayStart).first();
    const decision = decideThrottle(Number(windowRow?.count || 0), Number(dayRow?.total || 0));
    if (!decision.allowed) return json({ error: FEEDBACK_RATE_LIMITED_ERROR }, 429);
    await env.DB.prepare(`
      INSERT INTO feedback_rate_limit(fingerprint, window_start, count) VALUES(?, ?, 1)
      ON CONFLICT(fingerprint, window_start) DO UPDATE SET count = count + 1
    `).bind(fingerprint, windowStart).run();
  } catch {
    // 限流是 best-effort，忽略异常继续提交。
  }
  return null;
}

// 只记录状态码与错误标题，绝不记录 GITHUB_TOKEN 或完整正文。
async function createGithubIssue(env, issue, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(FEEDBACK_ISSUE_ENDPOINT, {
      method: "POST",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
        "User-Agent": "mocika-shield-stats-worker",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ title: issue.title, body: issue.body, labels: issue.labels }),
    });
  } catch {
    console.error("feedback: GitHub 请求失败");
    return null;
  }
  if (!response || response.ok !== true) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = typeof payload?.message === "string" ? payload.message : "";
    } catch {
      detail = "";
    }
    console.error("feedback: GitHub 创建 issue 失败", response?.status, detail);
    return null;
  }
  try {
    const payload = await response.json();
    if (!Number.isInteger(payload?.number) || typeof payload?.html_url !== "string") return null;
    return { number: payload.number, url: payload.html_url };
  } catch {
    return null;
  }
}

async function createFeedbackIssueUnsafe(request, env, now) {
  let text;
  try {
    text = await request.text();
  } catch {
    return json({ error: "请求数据格式无效" }, 400);
  }
  const byteLength = encoder.encode(text).byteLength;
  if (byteLength > MAX_FEEDBACK_BYTES) return json({ error: "反馈内容超过32768字节" }, 400);

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return json({ error: "请求数据格式无效" }, 400);
  }

  let feedback;
  try {
    feedback = normalizeFeedback(parsed, byteLength);
  } catch (error) {
    return json({ error: error?.message || "反馈内容无效" }, 400);
  }

  if (typeof env.GITHUB_TOKEN !== "string" || env.GITHUB_TOKEN.length === 0) {
    return json({ error: FEEDBACK_UNAVAILABLE_ERROR }, 503);
  }

  const throttled = await checkThrottle(request, env, now);
  if (throttled) return throttled;

  const issue = buildFeedbackIssue(feedback);
  const fetchImpl = typeof env.fetch === "function" ? env.fetch : globalThis.fetch;
  const created = await createGithubIssue(env, issue, fetchImpl);
  if (!created) return json({ error: FEEDBACK_UNAVAILABLE_ERROR }, 503);
  return json({ number: created.number, url: created.url }, 201);
}

export async function createFeedbackIssue(request, env, now = new Date()) {
  try {
    return await createFeedbackIssueUnsafe(request, env, now);
  } catch {
    return json({ error: FEEDBACK_UNAVAILABLE_ERROR }, 503);
  }
}
