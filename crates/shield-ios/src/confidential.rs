use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const MAX_SECRET_COUNT: usize = 256;
const MAX_SECRET_BYTES: usize = 8 * 1024;

pub(crate) fn copy_and_validate(source: &Path, target_directory: &Path) -> Result<()> {
    let content = fs::read_to_string(source)
        .with_context(|| format!("读取 Swift Confidential 配置失败：{}", source.display()))?;
    if content.len() > 1024 * 1024 {
        anyhow::bail!("Swift Confidential 配置超过 1 MiB 限制");
    }
    if !content
        .lines()
        .any(|line| line.trim_start().starts_with("secrets:"))
    {
        anyhow::bail!("Swift Confidential 配置缺少 secrets 列表");
    }
    fs::create_dir_all(target_directory)?;
    fs::write(target_directory.join("confidential.yml"), content)?;
    Ok(())
}

pub(crate) fn selected_literals(path: &Path) -> Result<Vec<Vec<u8>>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("读取敏感字符串配置失败：{}", path.display()))?;
    let mut values = Vec::new();
    let mut in_values = false;
    let mut values_indent = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some(value) = trimmed.strip_prefix("value:") {
            if value.trim().is_empty() {
                in_values = true;
                values_indent = indent;
            } else {
                push_literal(&mut values, value)?;
                in_values = false;
            }
            continue;
        }
        if trimmed == "values:" {
            in_values = true;
            values_indent = indent;
            continue;
        }
        if in_values && indent > values_indent {
            if let Some(value) = trimmed.strip_prefix('-') {
                push_literal(&mut values, value)?;
            }
            continue;
        }
        if indent <= values_indent {
            in_values = false;
        }
    }
    if values.len() > MAX_SECRET_COUNT {
        anyhow::bail!("敏感字符串数量超过 {MAX_SECRET_COUNT} 个限制");
    }
    Ok(values)
}

fn push_literal(values: &mut Vec<Vec<u8>>, raw: &str) -> Result<()> {
    let value = raw.trim();
    if value.is_empty() || value == "[]" {
        return Ok(());
    }
    let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        serde_json::from_str::<String>(value).context("解析 confidential.yml 双引号字符串失败")?
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value[1..value.len() - 1].replace("''", "'")
    } else {
        value.split(" #").next().unwrap_or(value).trim().to_string()
    };
    if value.len() > MAX_SECRET_BYTES {
        anyhow::bail!("单个敏感字符串超过 {MAX_SECRET_BYTES} 字节限制");
    }
    if !value.is_empty() {
        values.push(value.into_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_explicit_secret_values() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "algorithm: random\nsecrets:\n  - name: apiKey\n    value: \"secret-key\"\n  - name: pins\n    value:\n      - 'pin-one'\n      - pin-two # comment\n",
        )
        .unwrap();
        let values = selected_literals(temp.path()).unwrap();
        assert_eq!(
            values,
            vec![
                b"secret-key".to_vec(),
                b"pin-one".to_vec(),
                b"pin-two".to_vec()
            ]
        );
    }
}
