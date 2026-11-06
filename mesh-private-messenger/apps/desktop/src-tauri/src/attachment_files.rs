use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

const MAX_SIZE: u64 = 536_870_912;
const MAX_CHUNK: usize = 65_536;

struct Save {
    file: Option<File>,
    destination: PathBuf,
    temporary: PathBuf,
    expected: u64,
    written: u64,
    failed: bool,
}

impl Drop for Save {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.temporary);
    }
}

#[derive(Default)]
struct Saves {
    next: u64,
    active: HashMap<u64, Save>,
}

/// Paths enter only from the native system save dialog. Web calls receive an
/// opaque handle and can append bounded chunks, finish, or abort that handle.
#[derive(Default)]
pub struct AttachmentSaves(Mutex<Saves>);

impl AttachmentSaves {
    pub fn begin(&self, destination: PathBuf, expected: u64) -> Result<u64, String> {
        if expected == 0 || expected > MAX_SIZE {
            return Err("invalid_attachment_size".into());
        }
        let mut state = self.0.lock().map_err(|_| "attachment_save_unavailable")?;
        if state.active.len() >= 4 {
            return Err("too_many_attachment_saves".into());
        }
        state.next = state
            .next
            .checked_add(1)
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or("attachment_save_unavailable")?;
        let id = state.next;
        destination.file_name().ok_or("invalid_save_path")?;
        let temporary = destination.with_file_name(format!(
            ".morse-attachment-{}-{id}.partial",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&temporary)
            .map_err(|_| "attachment_not_saved")?;
        state.active.insert(
            id,
            Save {
                file: Some(file),
                destination,
                temporary,
                expected,
                written: 0,
                failed: false,
            },
        );
        Ok(id)
    }

    pub fn write(&self, id: u64, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let mut state = self.0.lock().map_err(|_| "attachment_save_unavailable")?;
        let save = state
            .active
            .get_mut(&id)
            .ok_or("attachment_save_not_found")?;
        if save.failed
            || offset != save.written
            || bytes.is_empty()
            || bytes.len() > MAX_CHUNK
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > save.expected)
        {
            return Err("invalid_attachment_range".into());
        }
        if save
            .file
            .as_mut()
            .ok_or("attachment_save_not_found")?
            .write_all(bytes)
            .is_err()
        {
            save.failed = true;
            return Err("attachment_not_saved".into());
        }
        save.written += bytes.len() as u64;
        Ok(())
    }

    pub fn finish(&self, id: u64) -> Result<(), String> {
        let mut save = self
            .0
            .lock()
            .map_err(|_| "attachment_save_unavailable")?
            .active
            .remove(&id)
            .ok_or("attachment_save_not_found")?;
        if save.failed || save.written != save.expected {
            return Err("attachment_incomplete".into());
        }
        let file = save.file.take().ok_or("attachment_save_not_found")?;
        file.sync_all().map_err(|_| "attachment_not_saved")?;
        drop(file);
        std::fs::rename(&save.temporary, &save.destination).map_err(|_| "attachment_not_saved")?;
        Ok(())
    }

    pub fn abort(&self, id: u64) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "attachment_save_unavailable")?
            .active
            .remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    fn directory() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "morse-file-ranges-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn abort_and_incomplete_finish_preserve_the_selected_existing_file() {
        let dir = directory();
        let path = dir.join("selected.bin");
        std::fs::write(&path, b"original").unwrap();
        let saves = AttachmentSaves::default();
        let id = saves.begin(path.clone(), 10).unwrap();
        saves.write(id, 0, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert!(saves.finish(id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let id = saves.begin(path.clone(), 10).unwrap();
        saves.write(id, 0, b"first").unwrap();
        saves.abort(id).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writes_are_bounded_contiguous_and_commit_only_at_exact_size() {
        let dir = directory();
        let path = dir.join("saved.bin");
        let saves = AttachmentSaves::default();
        assert!(saves.begin(path.clone(), 536_870_913).is_err());
        let id = saves.begin(path.clone(), 7).unwrap();
        assert!(saves.write(id, 1, b"x").is_err());
        assert!(saves.write(id, 0, &vec![0; 65_537]).is_err());
        saves.write(id, 0, b"hello").unwrap();
        assert!(saves.write(id, 0, b"hello").is_err());
        assert!(saves.write(id, 5, b"too long").is_err());
        saves.write(id, 5, b"!!").unwrap();
        saves.finish(id).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello!!");
        assert!(saves.write(id, 7, b"x").is_err());
        saves.abort(id).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dropping_active_saves_removes_partial_plaintext_and_limits_open_files() {
        let dir = directory();
        {
            let saves = AttachmentSaves::default();
            for n in 0..4 {
                let id = saves.begin(dir.join(format!("file-{n}")), 1).unwrap();
                saves.write(id, 0, b"x").unwrap();
            }
            assert!(saves.begin(dir.join("fifth"), 1).is_err());
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 4);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in std::fs::read_dir(&dir).unwrap() {
                    assert_eq!(
                        entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
            }
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
