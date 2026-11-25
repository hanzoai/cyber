//! Pure-Rust FIPS 180-4 SHA-256 implementation with streaming I/O support.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// Streaming SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);

        if self.block_len > 0 {
            let need = 64 - self.block_len;
            if data.len() < need {
                self.block[self.block_len..self.block_len + data.len()].copy_from_slice(data);
                self.block_len += data.len();
                return;
            }
            self.block[self.block_len..64].copy_from_slice(&data[..need]);
            let full = self.block;
            self.compress(&full);
            self.block_len = 0;
            data = &data[need..];
        }

        while data.len() >= 64 {
            let chunk: [u8; 64] = data[..64].try_into().expect("chunk length is 64");
            self.compress(&chunk);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = (self.total_bytes as u128) * 8;
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            for b in &mut self.block[self.block_len..64] {
                *b = 0;
            }
            let full = self.block;
            self.compress(&full);
            self.block_len = 0;
        }

        for b in &mut self.block[self.block_len..56] {
            *b = 0;
        }
        self.block[56..64].copy_from_slice(&(total_bits as u64).to_be_bytes());
        let full = self.block;
        self.compress(&full);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    to_hex(&digest(data))
}

pub fn to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hash_reader<R: Read>(reader: &mut R) -> io::Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize(), total))
}

pub fn hash_file(path: &Path) -> io::Result<([u8; 32], u64)> {
    let mut file = File::open(path)?;
    hash_reader(&mut file)
}

/// Single file hash entry inside a deterministic directory tree manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashEntry {
    pub rel_path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Deterministic SHA-256 verification summary for a file or directory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHashReport {
    pub root: String,
    pub tree_sha256: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub files: Vec<FileHashEntry>,
}

impl TreeHashReport {
    pub fn to_json(&self) -> String {
        let mut out = String::from("{");
        out.push_str(&format!("\"root\":{},", crate::json::quote(&self.root)));
        out.push_str(&format!(
            "\"tree_sha256\":{},",
            crate::json::quote(&self.tree_sha256)
        ));
        out.push_str(&format!("\"total_files\":{},", self.total_files));
        out.push_str(&format!("\"total_bytes\":{},", self.total_bytes));
        out.push_str("\"files\":[");
        for (idx, entry) in self.files.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"path\":{},\"sha256\":{},\"bytes\":{}}}",
                crate::json::quote(&entry.rel_path),
                crate::json::quote(&entry.sha256),
                entry.bytes,
            ));
        }
        out.push_str("]}");
        out
    }
}

fn collect_tree_files(
    base: &Path,
    current: &Path,
    excludes: &[String],
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(current)?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if excludes.iter().any(|ex| ex == &name) {
            continue;
        }
        let meta = entry.metadata()?;
        let path = entry.path();
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_tree_files(base, &path, excludes, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Computes a deterministic SHA-256 digest over a single file or directory tree.
///
/// The root `tree_sha256` hashes `<file_sha256>  <posix_rel_path>\n` lines in
/// lexicographical path order so the digest is independent of filesystem walk order.
pub fn hash_tree(root: &Path, excludes: &[String]) -> io::Result<TreeHashReport> {
    let meta = std::fs::metadata(root)?;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;

    if meta.is_file() {
        let (digest, bytes) = hash_file(root)?;
        let rel = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.to_string_lossy().into_owned());
        total_bytes = bytes;
        files.push(FileHashEntry {
            rel_path: rel,
            sha256: to_hex(&digest),
            bytes,
        });
    } else if meta.is_dir() {
        let mut paths = Vec::new();
        collect_tree_files(root, root, excludes, &mut paths)?;
        paths.sort_by(|a, b| a.0.cmp(&b.0));
        for (rel, full) in paths {
            let (digest, bytes) = hash_file(&full)?;
            total_bytes = total_bytes.saturating_add(bytes);
            files.push(FileHashEntry {
                rel_path: rel,
                sha256: to_hex(&digest),
                bytes,
            });
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be a regular file or directory",
        ));
    }

    let mut manifest = Sha256::new();
    for entry in &files {
        manifest.update(entry.sha256.as_bytes());
        manifest.update(b"  ");
        manifest.update(entry.rel_path.as_bytes());
        manifest.update(b"\n");
    }

    Ok(TreeHashReport {
        root: root.to_string_lossy().into_owned(),
        tree_sha256: manifest.finalize_hex(),
        total_files: files.len(),
        total_bytes,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_fips_180_4_vectors() {
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        let mut streaming = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            streaming.update(&chunk);
        }
        assert_eq!(
            streaming.finalize_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn deterministic_tree_hashing_and_tamper_detection() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("cyber_probe_tree_{}_{}", std::process::id(), nanos));
        let tree_a = base.join("a");
        let tree_b = base.join("b");
        std::fs::create_dir_all(tree_a.join("sub")).unwrap();
        std::fs::create_dir_all(tree_a.join(".git")).unwrap();
        std::fs::create_dir_all(tree_b.join("sub")).unwrap();

        std::fs::write(tree_a.join("z.txt"), b"hello").unwrap();
        std::fs::write(tree_a.join("sub/a.txt"), b"world").unwrap();
        std::fs::write(tree_a.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();

        // Create files in reverse order in tree_b.
        std::fs::write(tree_b.join("sub/a.txt"), b"world").unwrap();
        std::fs::write(tree_b.join("z.txt"), b"hello").unwrap();

        let excludes = vec![".git".to_string()];
        let rep_a = hash_tree(&tree_a, &excludes).unwrap();
        let rep_b = hash_tree(&tree_b, &excludes).unwrap();
        assert_eq!(rep_a.total_files, 2);
        assert_eq!(rep_a.total_bytes, 10);
        assert_eq!(rep_a.tree_sha256, rep_b.tree_sha256);
        assert_eq!(rep_a.files[0].rel_path, "sub/a.txt");
        assert_eq!(rep_a.files[1].rel_path, "z.txt");

        // Mutating a single byte changes tree_sha256.
        std::fs::write(tree_b.join("z.txt"), b"hell!").unwrap();
        let rep_c = hash_tree(&tree_b, &excludes).unwrap();
        assert_ne!(rep_a.tree_sha256, rep_c.tree_sha256);

        let _ = std::fs::remove_dir_all(&base);
    }
}
