-- 软件内问题反馈的哈希指纹限流表：只保存 sha256 摘要，不保存原始 IP。
CREATE TABLE IF NOT EXISTS feedback_rate_limit (
  fingerprint TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (fingerprint, window_start)
);
