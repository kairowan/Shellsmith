//! keytool 子进程的文本协议：固定编码和语言，不依赖桌面会话的区域设置。
use crate::utils::no_window_command;
use std::ffi::OsStr;
use std::process::Command;

/// 为 Java 工具固定 UTF-8 标准流和语言环境，同时保留 Windows 隐藏控制台行为。
/// keytool、jarsigner 等 `-J` 参数工具共用该约定；只配置本次子进程。
pub fn java_tool_command(path: impl AsRef<OsStr>) -> Command {
    let mut command = no_window_command(path);
    command.args([
        "-J-Dfile.encoding=UTF-8",
        // Java 8/17 的标准流与新 JDK 的标准流分别显式约定，未知属性不会改变工具参数。
        "-J-Dsun.stdout.encoding=UTF-8",
        "-J-Dsun.stderr.encoding=UTF-8",
        "-J-Dstdout.encoding=UTF-8",
        "-J-Dstderr.encoding=UTF-8",
        "-J-Duser.language=en",
        "-J-Duser.country=US",
    ]);
    command
}

/// 保留原有 keytool 调用入口，避免调用方重复维护编码参数。
pub fn keytool_command(path: impl AsRef<OsStr>) -> Command {
    java_tool_command(path)
}

#[cfg(test)]
mod tests {
    use super::java_tool_command;

    #[test]
    fn java_工具固定密码文件读取编码() {
        let command = java_tool_command("jarsigner");
        let args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|value| value == "-J-Dfile.encoding=UTF-8"));
        assert!(args
            .iter()
            .any(|value| value == "-J-Dstdout.encoding=UTF-8"));
        assert!(args
            .iter()
            .any(|value| value == "-J-Dstderr.encoding=UTF-8"));
    }
}
