use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

type Result<T> = std::result::Result<T, String>;

const MAX_KEY_TABLE_BYTES: usize = 1024 * 1024;
const MAX_KEYS: usize = 4096;

static WRAP_KEY: Mutex<Option<[u8; 16]>> = Mutex::new(None);
static SO_KEYS: OnceLock<Mutex<BTreeMap<String, [u8; 16]>>> = OnceLock::new();
static FUNCTION_GRANULAR: Mutex<bool> = Mutex::new(false);

extern "C" {
    fn mocika_aes128_gcm_decrypt(
        key: *const u8,
        key_len: usize,
        data: *const u8,
        data_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> bool;
}

fn keys() -> &'static Mutex<BTreeMap<String, [u8; 16]>> {
    SO_KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub fn initialize_wrap_key(key: [u8; 16]) -> Result<()> {
    *WRAP_KEY.lock().map_err(|_| "N01".to_string())? = Some(key);
    keys().lock().map_err(|_| "N02".to_string())?.clear();
    Ok(())
}

pub fn load_key_table(blob: &[u8]) -> Result<Vec<String>> {
    if blob.len() > MAX_KEY_TABLE_BYTES
        || blob.len() < 4 + 12 + 16 + 4
        || (&blob[..4] != b"PSOK" && &blob[..4] != b"PSO2")
    {
        return Err("N03".to_string());
    }
    let function_granular = &blob[..4] == b"PSO2";
    let wrap_key = WRAP_KEY
        .lock()
        .map_err(|_| "N04".to_string())?
        .ok_or_else(|| "N05".to_string())?;
    let encrypted = &blob[4..];
    let mut plain = vec![0u8; encrypted.len() - 28];
    let ok = unsafe {
        mocika_aes128_gcm_decrypt(
            wrap_key.as_ptr(),
            wrap_key.len(),
            encrypted.as_ptr(),
            encrypted.len(),
            plain.as_mut_ptr(),
            plain.len(),
        )
    };
    if !ok {
        plain.fill(0);
        return Err("N06".to_string());
    }
    let parsed = parse_key_table(&plain);
    plain.fill(0);
    let parsed = parsed?;
    let names = parsed.keys().cloned().collect::<Vec<_>>();
    *keys().lock().map_err(|_| "N07".to_string())? = parsed;
    *FUNCTION_GRANULAR.lock().map_err(|_| "N60".to_string())? = function_granular;
    Ok(names)
}

fn parse_key_table(plain: &[u8]) -> Result<BTreeMap<String, [u8; 16]>> {
    if plain.len() < 4 {
        return Err("N08".to_string());
    }
    let count = u32::from_le_bytes(plain[..4].try_into().map_err(|_| "N09")?) as usize;
    if count == 0 || count > MAX_KEYS || count > (plain.len() - 4) / 18 {
        return Err("N10".to_string());
    }
    let mut cursor = 4usize;
    let mut parsed = BTreeMap::new();
    for _ in 0..count {
        let name_len_end = cursor.checked_add(2).ok_or("N11")?;
        if name_len_end > plain.len() {
            return Err("N12".to_string());
        }
        let name_len = u16::from_le_bytes(plain[cursor..name_len_end].try_into().unwrap()) as usize;
        cursor = name_len_end;
        let name_end = cursor.checked_add(name_len).ok_or("N13")?;
        let key_end = name_end.checked_add(16).ok_or("N14")?;
        if name_len == 0 || name_len > 255 || key_end > plain.len() {
            return Err("N15".to_string());
        }
        let name = std::str::from_utf8(&plain[cursor..name_end])
            .map_err(|_| "N16".to_string())?
            .to_string();
        if !safe_basename(&name) {
            return Err("N17".to_string());
        }
        let key: [u8; 16] = plain[name_end..key_end].try_into().unwrap();
        if parsed.insert(name, key).is_some() {
            return Err("N18".to_string());
        }
        cursor = key_end;
    }
    if cursor != plain.len() {
        return Err("N19".to_string());
    }
    Ok(parsed)
}

fn safe_basename(name: &str) -> bool {
    name.starts_with("lib")
        && name.ends_with(".so")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

pub fn decrypt_so(name: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    if !safe_basename(name) {
        return Err("N20".to_string());
    }
    let key = keys()
        .lock()
        .map_err(|_| "N21".to_string())?
        .get(name)
        .copied()
        .ok_or_else(|| "N22".to_string())?;
    if *FUNCTION_GRANULAR.lock().map_err(|_| "N61".to_string())? {
        decrypt_elf_functions(encrypted, &key)
    } else {
        decrypt_elf_text(encrypted, &key)
    }
}

fn decrypt_elf_functions(encrypted: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    let ranges = elf_function_ranges(encrypted)?;
    if ranges.is_empty() {
        return Err("N62".to_string());
    }
    let mut output = encrypted.to_vec();
    for (offset, size) in ranges {
        let end = offset.checked_add(size).ok_or("N63")?;
        rc4_xor(key, output.get_mut(offset..end).ok_or("N64")?);
    }
    Ok(output)
}

fn decrypt_elf_text(encrypted: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    let (offset, size) = elf_text_range(encrypted)?;
    let end = offset.checked_add(size).ok_or("N23")?;
    let mut output = encrypted.to_vec();
    rc4_xor(key, &mut output[offset..end]);
    Ok(output)
}

fn elf_text_range(data: &[u8]) -> Result<(usize, usize)> {
    let (_, offset, size) = elf_text_info(data)?;
    Ok((offset, size))
}

fn elf_text_info(data: &[u8]) -> Result<(u64, usize, usize)> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[5] != 1 {
        return Err("N24".to_string());
    }
    let (shoff, shentsize, shnum, shstrndx, offset_field, size_field) = match data[4] {
        1 => (
            read_u32(data, 32)? as usize,
            read_u16(data, 46)? as usize,
            read_u16(data, 48)? as usize,
            read_u16(data, 50)? as usize,
            16usize,
            20usize,
        ),
        2 => (
            usize::try_from(read_u64(data, 40)?).map_err(|_| "N25")?,
            read_u16(data, 58)? as usize,
            read_u16(data, 60)? as usize,
            read_u16(data, 62)? as usize,
            24usize,
            32usize,
        ),
        _ => return Err("N26".to_string()),
    };
    let minimum = if data[4] == 1 { 40 } else { 64 };
    if shentsize < minimum || shnum == 0 || shstrndx >= shnum {
        return Err("N27".to_string());
    }
    let table_end = shoff
        .checked_add(shentsize.checked_mul(shnum).ok_or("N28")?)
        .ok_or("N29")?;
    if table_end > data.len() {
        return Err("N30".to_string());
    }
    let str_header = shoff + shentsize * shstrndx;
    let str_offset = read_word(data, str_header + offset_field, data[4])?;
    let str_size = read_word(data, str_header + size_field, data[4])?;
    let str_end = str_offset.checked_add(str_size).ok_or("N31")?;
    if str_end > data.len() {
        return Err("N32".to_string());
    }
    for index in 0..shnum {
        let header = shoff + shentsize * index;
        let name_offset = read_u32(data, header)? as usize;
        if name_offset >= str_size {
            continue;
        }
        let name_start = str_offset + name_offset;
        let relative_end = data[name_start..str_end]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("N33")?;
        if &data[name_start..name_start + relative_end] == b".text" {
            let offset = read_word(data, header + offset_field, data[4])?;
            let size = read_word(data, header + size_field, data[4])?;
            if size == 0 || !matches!(offset.checked_add(size), Some(end) if end <= data.len()) {
                return Err("N34".to_string());
            }
            let address = read_word(data, header + if data[4] == 1 { 12 } else { 16 }, data[4])?;
            return Ok((address as u64, offset, size));
        }
    }
    Err("N35".to_string())
}

fn elf_function_ranges(data: &[u8]) -> Result<Vec<(usize, usize)>> {
    let (text_address, text_offset, text_size) = elf_text_info(data)?;
    let text_end = text_address
        .checked_add(u64::try_from(text_size).map_err(|_| "N65")?)
        .ok_or("N66")?;
    let class = data[4];
    let (shoff, shentsize, shnum) = match class {
        1 => (
            read_u32(data, 32)? as usize,
            read_u16(data, 46)? as usize,
            read_u16(data, 48)? as usize,
        ),
        2 => (
            usize::try_from(read_u64(data, 40)?).map_err(|_| "N67")?,
            read_u16(data, 58)? as usize,
            read_u16(data, 60)? as usize,
        ),
        _ => return Err("N68".to_string()),
    };
    let mut ranges = Vec::new();
    for index in 0..shnum {
        let header = shoff
            .checked_add(shentsize.checked_mul(index).ok_or("N69")?)
            .ok_or("N70")?;
        let section_type = read_u32(data, header + 4)?;
        if section_type != 2 && section_type != 11 {
            continue;
        }
        let (offset_field, size_field, entsize_field, default_entry) = if class == 1 {
            (16usize, 20usize, 36usize, 16usize)
        } else {
            (24usize, 32usize, 56usize, 24usize)
        };
        let table_offset = read_word(data, header + offset_field, class)?;
        let table_size = read_word(data, header + size_field, class)?;
        let mut entry_size = read_word(data, header + entsize_field, class)?;
        if entry_size == 0 {
            entry_size = default_entry;
        }
        if entry_size < default_entry || table_size % entry_size != 0 {
            return Err("N71".to_string());
        }
        let table_end = table_offset.checked_add(table_size).ok_or("N72")?;
        if table_end > data.len() {
            return Err("N73".to_string());
        }
        let mut cursor = table_offset;
        while cursor < table_end {
            let (info, value, size, shndx) = if class == 1 {
                (
                    *data.get(cursor + 12).ok_or("N74")?,
                    read_u32(data, cursor + 4)? as u64,
                    read_u32(data, cursor + 8)? as u64,
                    read_u16(data, cursor + 14)?,
                )
            } else {
                (
                    *data.get(cursor + 4).ok_or("N75")?,
                    read_u64(data, cursor + 8)?,
                    read_u64(data, cursor + 16)?,
                    read_u16(data, cursor + 6)?,
                )
            };
            let value = value & !1;
            let end = value.checked_add(size).ok_or("N76")?;
            if info & 0x0f == 2
                && shndx != 0
                && size > 0
                && value >= text_address
                && end <= text_end
            {
                let relative = usize::try_from(value - text_address).map_err(|_| "N77")?;
                let offset = text_offset.checked_add(relative).ok_or("N78")?;
                let size = usize::try_from(size).map_err(|_| "N79")?;
                if matches!(offset.checked_add(size), Some(end) if end <= data.len()) {
                    ranges.push((offset, size));
                }
            }
            cursor = cursor.checked_add(entry_size).ok_or("N80")?;
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (offset, size) in ranges {
        if let Some((previous_offset, previous_size)) = merged.last_mut() {
            let previous_end = previous_offset.checked_add(*previous_size).ok_or("N81")?;
            if offset <= previous_end {
                let end = offset.checked_add(size).ok_or("N82")?;
                *previous_size = previous_end.max(end) - *previous_offset;
                continue;
            }
        }
        merged.push((offset, size));
    }
    Ok(merged)
}

fn read_word(data: &[u8], offset: usize, class: u8) -> Result<usize> {
    if class == 1 {
        Ok(read_u32(data, offset)? as usize)
    } else {
        usize::try_from(read_u64(data, offset)?).map_err(|_| "N36".to_string())
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or("N37")?;
    Ok(u16::from_le_bytes(
        data.get(offset..end).ok_or("N38")?.try_into().unwrap(),
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or("N39")?;
    Ok(u32::from_le_bytes(
        data.get(offset..end).ok_or("N40")?.try_into().unwrap(),
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or("N41")?;
    Ok(u64::from_le_bytes(
        data.get(offset..end).ok_or("N42")?.try_into().unwrap(),
    ))
}

fn rc4_xor(key: &[u8], data: &mut [u8]) {
    let mut state = [0u8; 256];
    for (index, value) in state.iter_mut().enumerate() {
        *value = index as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) & 0xff;
        state.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    for byte in data {
        i = (i + 1) & 0xff;
        j = (j + state[i] as usize) & 0xff;
        state.swap(i, j);
        *byte ^= state[(state[i] as usize + state[j] as usize) & 0xff];
    }
    state.fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf32_fixture() -> Vec<u8> {
        let mut elf = vec![0u8; 0x180];
        elf[..6].copy_from_slice(b"\x7fELF\x01\x01");
        elf[32..36].copy_from_slice(&0x80u32.to_le_bytes());
        elf[46..48].copy_from_slice(&40u16.to_le_bytes());
        elf[48..50].copy_from_slice(&3u16.to_le_bytes());
        elf[50..52].copy_from_slice(&1u16.to_le_bytes());
        let shstr = 0x80 + 40;
        elf[shstr + 16..shstr + 20].copy_from_slice(&0x110u32.to_le_bytes());
        elf[shstr + 20..shstr + 24].copy_from_slice(&7u32.to_le_bytes());
        elf[0x110..0x117].copy_from_slice(b"\0.text\0");
        let text = 0x80 + 80;
        elf[text..text + 4].copy_from_slice(&1u32.to_le_bytes());
        elf[text + 16..text + 20].copy_from_slice(&0x140u32.to_le_bytes());
        elf[text + 20..text + 24].copy_from_slice(&16u32.to_le_bytes());
        for (index, byte) in elf[0x140..0x150].iter_mut().enumerate() {
            *byte = index as u8;
        }
        elf
    }

    #[test]
    fn rc4_elf_text_is_reversible_and_leaves_other_bytes() {
        let original = elf32_fixture();
        let encrypted = decrypt_elf_text(&original, &[7u8; 16]).unwrap();
        assert_ne!(&encrypted[0x140..0x150], &original[0x140..0x150]);
        assert_eq!(&encrypted[..0x140], &original[..0x140]);
        assert_eq!(decrypt_elf_text(&encrypted, &[7u8; 16]).unwrap(), original);
    }

    #[test]
    fn malformed_elf_is_rejected() {
        assert!(decrypt_elf_text(b"not an elf", &[0u8; 16]).is_err());
    }

    #[test]
    fn function_granular_mode_requires_symbol_ranges() {
        assert!(decrypt_elf_functions(&elf32_fixture(), &[7u8; 16]).is_err());
    }
}
