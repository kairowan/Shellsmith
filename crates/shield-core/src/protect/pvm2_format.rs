//! Xop PVM2 镜像格式版本的构建期握手。
//!
//! 打包器把 `Pvm2Opcodes.VERSION` 写进每个 PVM2 镜像头部，壳运行时（静态链入的
//! Xop 解释器）用自身的 `PVM2_VERSION_V*` 上限校验它。两侧取自不同 XopProtector
//! 源码时，运行时会在设备上拒绝镜像：
//!
//! ```text
//! E protector: PVM2 unsupported version 6
//! java.lang.RuntimeException: VMP not ready
//! ```
//!
//! 被保护方法无法分派，调用它的应用在启动阶段直接崩溃。这个不一致只在真机上暴露，
//! 所以这里在打包前比对两侧版本，不匹配就失败关闭，而不是产出启动即崩的安装包。

use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 打包器 JAR 中记录镜像格式版本的类。
const OPCODES_CLASS: &str = "com/yqsh/protector/packer/Pvm2Opcodes.class";
/// 该类中承载版本号的静态字段名。
const OPCODES_VERSION_FIELD: &str = "VERSION";

/// 读取打包器 JAR 声明的 PVM2 镜像格式版本。
///
/// `Ok(None)` 表示 JAR 中没有该字段（不是 Xop 打包器，或上游结构变了）；
/// 这种情况跳过比对，避免把未知当成不兼容。
pub(crate) fn packer_format_version(jar: &Path) -> Result<Option<u32>> {
    let file =
        File::open(jar).with_context(|| format!("打开 PVM2 打包器失败：{}", jar.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("解析 PVM2 打包器 JAR 失败：{}", jar.display()))?;
    let mut class = Vec::new();
    match archive.by_name(OPCODES_CLASS) {
        Ok(mut entry) => {
            entry
                .read_to_end(&mut class)
                .with_context(|| format!("读取 {OPCODES_CLASS} 失败"))?;
        }
        Err(_) => return Ok(None),
    }
    Ok(static_int_constant(&class, OPCODES_VERSION_FIELD))
}

/// 比对打包器与壳运行时的 PVM2 格式版本。
///
/// 运行时兼容更旧的格式，所以只有打包器更新才拒绝；`runtime_max` 为 `None`
/// 表示旧资源包没有声明版本，此时跳过比对。
pub(crate) fn verify_format_compatibility(packer: &Path, runtime_max: Option<u32>) -> Result<()> {
    let Some(packer_version) = packer_format_version(packer)? else {
        return Ok(());
    };
    let Some(runtime_version) = runtime_max else {
        return Ok(());
    };
    if packer_version <= runtime_version {
        return Ok(());
    }
    anyhow::bail!(
        "PVM2 格式版本不一致：打包器产出 v{packer_version}，壳运行时最高只支持 v{runtime_version}。\
         打包器与运行时源码都在本仓库 third_party/xopprotector：请用该目录的源码重建壳运行时\
         （make build-stub）与 tools/xop-pvm2-packer.jar，或改用与当前运行时匹配的打包器 JAR。\
         继续打包会产出在设备上启动即崩的安装包（运行时报 PVM2 unsupported version {packer_version}）"
    );
}

/// 从 class 文件字节中读取某个静态 int 字段的 `ConstantValue`。
///
/// 只需要常量池里的 Utf8 与 Integer，但必须完整跳过其余所有常量类型
/// （Long / Double 占两个槽位），否则索引会整体错位。
fn static_int_constant(bytes: &[u8], field: &str) -> Option<u32> {
    let mut cursor = Cursor { bytes, pos: 0 };
    if cursor.u4()? != 0xCAFE_BABE {
        return None;
    }
    cursor.skip(4)?; // minor_version + major_version
    let pool = constant_pool(&mut cursor)?;
    cursor.skip(2)?; // access_flags
    cursor.skip(2)?; // this_class
    cursor.skip(2)?; // super_class
    let interfaces = cursor.u2()? as usize;
    cursor.skip(interfaces * 2)?;
    let fields = cursor.u2()? as usize;
    for _ in 0..fields {
        cursor.skip(2)?; // access_flags
        let name_index = cursor.u2()? as usize;
        cursor.skip(2)?; // descriptor_index
        let attributes = cursor.u2()? as usize;
        let name = pool.utf8.get(name_index).and_then(|value| value.as_deref());
        let mut value = None;
        for _ in 0..attributes {
            let attribute_name_index = cursor.u2()? as usize;
            let attribute_length = cursor.u4()? as usize;
            let attribute_name = pool
                .utf8
                .get(attribute_name_index)
                .and_then(|entry| entry.as_deref());
            if attribute_name == Some("ConstantValue") && attribute_length == 2 {
                let index = cursor.u2()? as usize;
                value = pool.integers.get(index).copied().flatten();
            } else {
                cursor.skip(attribute_length)?;
            }
        }
        if name == Some(field) {
            return value;
        }
    }
    None
}

/// 按常量池索引对齐的 Utf8 文本与 Integer 值。
struct ConstantPool {
    utf8: Vec<Option<String>>,
    integers: Vec<Option<u32>>,
}

/// 解析常量池，返回按索引对齐的 Utf8 文本与 Integer 值。
fn constant_pool(cursor: &mut Cursor) -> Option<ConstantPool> {
    let count = cursor.u2()? as usize;
    let mut utf8 = vec![None; count];
    let mut integers = vec![None; count];
    let mut index = 1;
    while index < count {
        let tag = cursor.u1()?;
        match tag {
            1 => {
                let length = cursor.u2()? as usize;
                let bytes = cursor.take(length)?;
                utf8[index] = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            3 => integers[index] = Some(cursor.u4()?),
            4 => cursor.skip(4)?, // Float
            5 | 6 => {
                cursor.skip(8)?; // Long / Double 占两个常量池槽位
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => cursor.skip(2)?,
            9..=12 | 17 | 18 => cursor.skip(4)?,
            15 => cursor.skip(3)?,
            _ => return None,
        }
        index += 1;
    }
    Some(ConstantPool { utf8, integers })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(length)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(|_| ())
    }

    fn u1(&mut self) -> Option<u8> {
        self.take(1).map(|slice| slice[0])
    }

    fn u2(&mut self) -> Option<u16> {
        self.take(2)
            .map(|slice| u16::from_be_bytes([slice[0], slice[1]]))
    }

    fn u4(&mut self) -> Option<u32> {
        self.take(4)
            .map(|slice| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 组装一个只含 `public static final int VERSION = <value>` 的最小 class 文件。
    /// `pad_long` 为真时先插入一个 Long 常量，用来验证两个槽位的跳过逻辑。
    fn synthetic_class(value: u32, field: &str, pad_long: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // minor
        out.extend_from_slice(&52u16.to_be_bytes()); // major
        let count: u16 = if pad_long { 6 } else { 5 };
        out.extend_from_slice(&count.to_be_bytes());
        // #1 Utf8 字段名
        out.push(1);
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
        // #2 Utf8 描述符
        out.push(1);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(b'I');
        // #3 Utf8 属性名
        out.push(1);
        out.extend_from_slice(&13u16.to_be_bytes());
        out.extend_from_slice(b"ConstantValue");
        // #4 Integer 值
        out.push(3);
        out.extend_from_slice(&value.to_be_bytes());
        if pad_long {
            // #5 Long（占 #5、#6 两个槽位）
            out.push(5);
            out.extend_from_slice(&0u64.to_be_bytes());
        }
        out.extend_from_slice(&0x0019u16.to_be_bytes()); // access_flags
        out.extend_from_slice(&0u16.to_be_bytes()); // this_class
        out.extend_from_slice(&0u16.to_be_bytes()); // super_class
        out.extend_from_slice(&0u16.to_be_bytes()); // interfaces_count
        out.extend_from_slice(&1u16.to_be_bytes()); // fields_count
        out.extend_from_slice(&0x0019u16.to_be_bytes()); // field access_flags
        out.extend_from_slice(&1u16.to_be_bytes()); // name_index
        out.extend_from_slice(&2u16.to_be_bytes()); // descriptor_index
        out.extend_from_slice(&1u16.to_be_bytes()); // attributes_count
        out.extend_from_slice(&3u16.to_be_bytes()); // attribute_name_index
        out.extend_from_slice(&2u32.to_be_bytes()); // attribute_length
        out.extend_from_slice(&4u16.to_be_bytes()); // constantvalue_index
        out
    }

    fn temp_jar(class: Option<Vec<u8>>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("packer.jar");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        if let Some(class) = class {
            zip.start_file(OPCODES_CLASS, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(&class).unwrap();
        }
        zip.start_file("other.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"x").unwrap();
        zip.finish().unwrap();
        dir
    }

    #[test]
    fn 读取打包器声明的格式版本() {
        assert_eq!(
            static_int_constant(&synthetic_class(6, "VERSION", false), "VERSION"),
            Some(6)
        );
        assert_eq!(
            static_int_constant(&synthetic_class(5, "VERSION", false), "VERSION"),
            Some(5)
        );
    }

    #[test]
    fn 常量池中的_long_占两个槽位不会让索引错位() {
        assert_eq!(
            static_int_constant(&synthetic_class(7, "VERSION", true), "VERSION"),
            Some(7)
        );
    }

    #[test]
    fn 字段名不匹配或结构损坏时返回未知() {
        assert_eq!(
            static_int_constant(&synthetic_class(6, "VERSION", false), "OTHER"),
            None
        );
        assert_eq!(static_int_constant(&[], "VERSION"), None);
        assert_eq!(
            static_int_constant(&[0xCA, 0xFE, 0xBA, 0xBE], "VERSION"),
            None
        );
        let mut truncated = synthetic_class(6, "VERSION", false);
        truncated.truncate(truncated.len() - 4);
        assert_eq!(static_int_constant(&truncated, "VERSION"), None);
    }

    #[test]
    fn 从真实_jar_读出打包器版本() {
        let dir = temp_jar(Some(synthetic_class(6, "VERSION", false)));
        let jar = dir.path().join("packer.jar");
        assert_eq!(packer_format_version(&jar).unwrap(), Some(6));
    }

    #[test]
    fn jar_中缺少该字段时按未知处理() {
        let dir = temp_jar(None);
        let jar = dir.path().join("packer.jar");
        assert_eq!(packer_format_version(&jar).unwrap(), None);
    }

    #[test]
    fn 打包器更新于运行时则拒绝并给出修复建议() {
        let dir = temp_jar(Some(synthetic_class(6, "VERSION", false)));
        let jar = dir.path().join("packer.jar");
        let error = verify_format_compatibility(&jar, Some(5))
            .unwrap_err()
            .to_string();
        assert!(error.contains("v6"));
        assert!(error.contains("v5"));
        assert!(error.contains("make build-stub"));
        assert!(error.contains("PVM2 unsupported version 6"));
    }

    #[test]
    fn 版本一致运行时更新或缺少声明时放行() {
        let dir = temp_jar(Some(synthetic_class(6, "VERSION", false)));
        let jar = dir.path().join("packer.jar");
        assert!(verify_format_compatibility(&jar, Some(6)).is_ok());
        // 运行时支持更旧的格式，不算不兼容。
        assert!(verify_format_compatibility(&jar, Some(9)).is_ok());
        // 旧资源包没有声明版本，跳过比对。
        assert!(verify_format_compatibility(&jar, None).is_ok());

        let unknown = temp_jar(None);
        assert!(verify_format_compatibility(&unknown.path().join("packer.jar"), Some(5)).is_ok());
    }

    /// 内置打包器 JAR 是随仓库分发的产物；测试固定校验它与发布运行时同源，
    /// 并复现"运行时落后一版"的现场，防止再次把不匹配的组合发出去。
    #[test]
    fn 内置打包器_jar_与发布运行时的格式版本一致() {
        let jar = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/xop-pvm2-packer.jar");
        let version = packer_format_version(&jar)
            .expect("应能解析内置打包器")
            .expect("内置打包器必须声明 PVM2 格式版本");
        assert!(version >= 1);

        // 运行时由仓库内 third_party/xopprotector 编译；两者同版本时必须放行。
        verify_format_compatibility(&jar, Some(version)).expect("同版本必须放行");

        // 运行时落后时必须在打包前拒绝，而不是产出启动即崩的包。
        if version >= 2 {
            let error = verify_format_compatibility(&jar, Some(version - 1))
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!("v{version}")), "{error}");
            assert!(error.contains(&format!("v{}", version - 1)), "{error}");
        }
    }
}
