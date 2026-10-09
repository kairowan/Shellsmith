import assert from "node:assert/strict";
import test from "node:test";

import {
  FEEDBACK_MARKER,
  buildFeedbackIssue,
  createFeedbackIssue,
  decideThrottle,
  ensureFeedbackMarker,
  fingerprintWindow,
  normalizeFeedback,
} from "./feedback.js";
import worker from "./index.js";

const ISSUE_URL = "https://api.github.com/repos/kairowan/Shellsmith/issues";
const NOW = new Date("2026-09-24T12:37:45.000Z");

function validBug(overrides = {}) {
  return {
    schema_version: 1,
    kind: "bug",
    title: "加固后安装失败",
    body: "### 问题模块\n\n加固（Android）\n\n### 复现步骤\n\n1. 选择 APK\n2. 开始加固",
    app_version: "1.4.0",
    ...overrides,
  };
}

function validFeature(overrides = {}) {
  return {
    schema_version: 1,
    kind: "feature",
    title: "支持批量签名",
    body: "### 功能分类\n\n签名\n\n### 使用场景\n\n在 CI 中批量签名",
    app_version: "1.4.0-beta.1",
    ...overrides,
  };
}

// 假 D1：只实现限流用到的最小接口，可注入窗口计数与异常。
function createFakeDb({ windowCount = 0, dayCount = 0, failOnPrepare = false } = {}) {
  const writes = [];
  return {
    writes,
    prepare(sql) {
      if (failOnPrepare) throw new Error("no such table: feedback_rate_limit");
      const statement = {
        sql,
        values: [],
        bind(...values) { statement.values = values; return statement; },
        async first() {
          if (sql.includes("SUM(count)")) return { total: dayCount };
          return windowCount > 0 ? { count: windowCount } : null;
        },
        async run() { writes.push({ sql, values: statement.values }); return { success: true }; },
      };
      return statement;
    },
  };
}

// 假 fetch：记录调用，不发真实网络请求。
function createFakeFetch({
  ok = true,
  status = 201,
  payload = { number: 12, html_url: "https://github.com/kairowan/Shellsmith/issues/12" },
  throwOnCall = false,
} = {}) {
  const calls = [];
  const impl = async (url, init) => {
    if (throwOnCall) throw new Error("网络不可达");
    calls.push({ url, init });
    return { ok, status, async json() { return payload; } };
  };
  impl.calls = calls;
  return { impl, calls };
}

function createEnv({ db, fetchImpl, token = "test-token" } = {}) {
  const env = {};
  if (db) env.DB = db;
  if (token !== null) env.GITHUB_TOKEN = token;
  if (fetchImpl) env.fetch = fetchImpl;
  return env;
}

function createRequest(body, ip = "203.0.113.9") {
  const headers = { "Content-Type": "application/json" };
  if (ip !== null) headers["CF-Connecting-IP"] = ip;
  return new Request("https://stats.invalid/reports/feedback", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

test("合法缺陷反馈创建 issue 并原样透传客户端正文", async () => {
  const db = createFakeDb();
  const { impl, calls } = createFakeFetch();
  const response = await createFeedbackIssue(createRequest(validBug()), createEnv({ db, fetchImpl: impl }), NOW);

  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), {
    number: 12,
    url: "https://github.com/kairowan/Shellsmith/issues/12",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, ISSUE_URL);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Accept, "application/vnd.github+json");
  assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
  assert.equal(calls[0].init.headers["User-Agent"], "mocika-shield-stats-worker");
  assert.equal(calls[0].init.headers["X-GitHub-Api-Version"], "2022-11-28");
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");

  const payload = JSON.parse(calls[0].init.body);
  assert.equal(payload.title, "[Bug] 加固后安装失败");
  assert.deepEqual(payload.labels, ["bug"]);
  assert.equal(payload.body, `${FEEDBACK_MARKER}\n${validBug().body}`);
  assert.equal(payload.body.includes("反馈来源"), false);

  // 限流只写入哈希指纹，不落库原始 IP。
  assert.equal(db.writes.length, 1);
  assert.match(db.writes[0].values[0], /^[0-9a-f]{64}$/);
  assert.equal(db.writes[0].values[0].includes("203.0.113.9"), false);
  assert.equal(db.writes[0].values[1], "2026-09-24T12:30");
});

test("合法功能建议创建 issue 并使用 enhancement 标签", async () => {
  const db = createFakeDb();
  const { impl, calls } = createFakeFetch();
  const response = await createFeedbackIssue(createRequest(validFeature()), createEnv({ db, fetchImpl: impl }));

  assert.equal(response.status, 201);
  const payload = JSON.parse(calls[0].init.body);
  assert.equal(payload.title, "[功能建议] 支持批量签名");
  assert.deepEqual(payload.labels, ["enhancement"]);
  assert.equal(payload.body, `${FEEDBACK_MARKER}\n${validFeature().body}`);
});

test("正文隐藏标记幂等：缺失时补在最前面，已有时不重复添加", async () => {
  assert.equal(ensureFeedbackMarker("### 问题模块"), `${FEEDBACK_MARKER}\n### 问题模块`);
  const marked = `${FEEDBACK_MARKER}\n\n### 问题模块`;
  assert.equal(ensureFeedbackMarker(marked), marked);
  assert.equal(buildFeedbackIssue(validBug({ body: marked })).body, marked);

  const { impl, calls } = createFakeFetch();
  const response = await createFeedbackIssue(createRequest(validBug({ body: marked })), createEnv({ fetchImpl: impl }));
  assert.equal(response.status, 201);
  assert.equal(JSON.parse(calls[0].init.body).body.split(FEEDBACK_MARKER).length - 1, 1);
});

test("固定字段协议拒绝未知字段、缺字段、类型不符与超长内容", async () => {
  const { impl, calls } = createFakeFetch();
  const env = createEnv({ db: createFakeDb(), fetchImpl: impl });
  const missingBody = { ...validBug() };
  delete missingBody.body;

  const cases = [
    [{ ...validBug(), raw_log: "额外字段" }, /反馈字段无效/],
    [missingBody, /反馈字段无效/],
    [validBug({ schema_version: 2 }), /协议版本无效/],
    [validBug({ kind: "question" }), /反馈类型无效/],
    [validBug({ title: "" }), /标题为空或过长/],
    [validBug({ title: "标".repeat(121) }), /标题为空或过长/],
    [validBug({ title: 123 }), /标题为空或过长/],
    [validBug({ body: "" }), /反馈正文为空或过长/],
    [validBug({ body: "a".repeat(24001) }), /反馈正文为空或过长/],
    [validBug({ body: null }), /反馈正文为空或过长/],
    [validBug({ app_version: "1.4" }), /应用版本无效/],
    [validBug({ app_version: "内部版本" }), /应用版本无效/],
    ["不是 JSON 对象", /反馈格式无效|请求数据格式无效/],
  ];

  for (const [body, pattern] of cases) {
    const response = await createFeedbackIssue(createRequest(body), env);
    assert.equal(response.status, 400, JSON.stringify(body).slice(0, 60));
    assert.match((await response.json()).error, pattern);
  }
  assert.equal(calls.length, 0);
});

test("请求体超过32KiB时返回400且不调用 GitHub", async () => {
  const { impl, calls } = createFakeFetch();
  const oversized = await createFeedbackIssue(
    createRequest(validBug({ body: "问".repeat(24000) })),
    createEnv({ db: createFakeDb(), fetchImpl: impl }),
  );
  assert.equal(oversized.status, 400);
  assert.match((await oversized.json()).error, /32768/);
  assert.throws(() => normalizeFeedback(validBug(), 32769), /32768/);
  const invalidJson = await createFeedbackIssue(createRequest("{"), createEnv({ db: createFakeDb(), fetchImpl: impl }));
  assert.equal(invalidJson.status, 400);
  assert.match((await invalidJson.json()).error, /请求数据格式无效/);
  assert.equal(calls.length, 0);
});

test("缺少 GITHUB_TOKEN 时返回可诊断失败且不调用 GitHub", async () => {
  for (const token of [null, ""]) {
    const { impl, calls } = createFakeFetch();
    const response = await createFeedbackIssue(
      createRequest(validBug()),
      createEnv({ db: createFakeDb(), fetchImpl: impl, token }),
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "反馈服务暂时不可用" });
    assert.equal(calls.length, 0);
  }
});

test("GitHub 非2xx或网络异常时失败且不泄露 token 与正文", async () => {
  const logs = [];
  const original = console.error;
  console.error = (...values) => logs.push(values.join(" "));
  try {
    const rejected = createFakeFetch({ ok: false, status: 422, payload: { message: "Validation Failed" } });
    const failed = await createFeedbackIssue(
      createRequest(validBug()),
      createEnv({ db: createFakeDb(), fetchImpl: rejected.impl }),
    );
    assert.equal(failed.status, 503);
    assert.deepEqual(await failed.json(), { error: "反馈服务暂时不可用" });

    const broken = createFakeFetch({ throwOnCall: true });
    const unreachable = await createFeedbackIssue(
      createRequest(validBug()),
      createEnv({ db: createFakeDb(), fetchImpl: broken.impl }),
    );
    assert.equal(unreachable.status, 503);

    const joined = logs.join("\n");
    assert.equal(joined.includes("test-token"), false);
    assert.equal(joined.includes(validBug().body), false);
    assert.equal(joined.includes("422"), true);
    assert.equal(joined.includes("Validation Failed"), true);
  } finally {
    console.error = original;
  }
});

test("限流窗口按10分钟粒度对齐并区分当天起点", () => {
  assert.deepEqual(fingerprintWindow(new Date("2026-09-24T12:37:45.000Z")), {
    windowStart: "2026-09-24T12:30",
    dayStart: "2026-09-24T00:00",
  });
  assert.equal(fingerprintWindow(new Date("2026-09-24T12:00:00.000Z")).windowStart, "2026-09-24T12:00");
  assert.equal(fingerprintWindow(new Date("2026-09-24T12:09:59.000Z")).windowStart, "2026-09-24T12:00");
  assert.equal(fingerprintWindow(new Date("2026-09-24T23:59:59.000Z")).windowStart, "2026-09-24T23:50");
  assert.deepEqual(fingerprintWindow(new Date("2026-09-25T00:00:00.000Z")), {
    windowStart: "2026-09-25T00:00",
    dayStart: "2026-09-25T00:00",
  });
  assert.throws(() => fingerprintWindow("不是时间"), /时间无效/);
});

test("限流判定在10分钟窗口内最多1次且当天最多20次", () => {
  assert.deepEqual(decideThrottle(0, 0), { allowed: true, reason: null });
  assert.deepEqual(decideThrottle(0, 19), { allowed: true, reason: null });
  assert.deepEqual(decideThrottle(1, 0), { allowed: false, reason: "window" });
  assert.deepEqual(decideThrottle(1, 19), { allowed: false, reason: "window" });
  assert.deepEqual(decideThrottle(0, 20), { allowed: false, reason: "day" });
  assert.deepEqual(decideThrottle(2, 25), { allowed: false, reason: "window" });
});

test("同一指纹超限时返回429且不创建 issue", async () => {
  const { impl, calls } = createFakeFetch();
  const response = await createFeedbackIssue(
    createRequest(validBug()),
    createEnv({ db: createFakeDb({ windowCount: 1, dayCount: 1 }), fetchImpl: impl }),
  );
  assert.equal(response.status, 429);
  assert.deepEqual(await response.json(), { error: "提交过于频繁，请稍后再试" });
  assert.equal(calls.length, 0);
});

test("D1 抛异常时限流失效但提交仍成功", async () => {
  const { impl, calls } = createFakeFetch();
  const response = await createFeedbackIssue(
    createRequest(validBug()),
    createEnv({ db: createFakeDb({ failOnPrepare: true }), fetchImpl: impl }),
  );
  assert.equal(response.status, 201);
  assert.equal(calls.length, 1);
});

test("缺少 CF-Connecting-IP 时用 unknown 计算指纹且不阻断提交", async () => {
  const db = createFakeDb();
  const { impl } = createFakeFetch();
  const response = await createFeedbackIssue(
    createRequest(validBug(), null),
    createEnv({ db, fetchImpl: impl }),
  );
  assert.equal(response.status, 201);
  assert.match(db.writes[0].values[0], /^[0-9a-f]{64}$/);
});

test("POST /reports/feedback 已注册到路由表", async () => {
  const { impl } = createFakeFetch();
  const response = await worker.fetch(
    createRequest(validBug()),
    createEnv({ db: createFakeDb(), fetchImpl: impl }),
    {},
  );
  assert.equal(response.status, 201);
});

test("标题与正文按码点计数，含 emoji 的内容不会被误判超长", () => {
  // 120 个 emoji 的 UTF-16 长度是 240，按码点算正好等于上限，不应被判为超长。
  const emojiTitle = "🚀".repeat(120);
  assert.equal(emojiTitle.length, 240);
  assert.doesNotThrow(() => normalizeFeedback(validBug({ title: emojiTitle })));
  assert.throws(() => normalizeFeedback(validBug({ title: "🚀".repeat(121) })), /标题为空或过长/);
  // 码点未超限但字节数超限时仍按字节上限拒绝，这与客户端的预校验口径一致。
  assert.throws(() => normalizeFeedback(validBug({ body: "🚀".repeat(24000) })), /32768/);
  assert.doesNotThrow(() => normalizeFeedback(validBug({ body: "🚀".repeat(2000) })));
});
