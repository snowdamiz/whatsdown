//! A download over 16 MiB is saved as it arrives: the save dialog picks the
//! file first, each decrypted chunk is appended, and a download that fails
//! removes what it wrote. The web view never holds the whole file.

use std::{collections::HashMap, fs::File, io::Write, path::PathBuf, sync::Mutex};

// One opened attachment chunk.
const MAX_CHUNK: usize = 65_536;

#[derive(Default)]
pub struct Saves {
    open: Mutex<(u32, HashMap<u32, (PathBuf, File)>)>,
}

impl Saves {
    pub fn start(&self, path: PathBuf) -> Result<u32, String> {
        let file = File::create(&path).map_err(|_| "attachment_not_saved")?;
        let mut open = self.open.lock().map_err(|_| "attachment_not_saved")?;
        open.0 = open.0.wrapping_add(1);
        let id = open.0;
        open.1.insert(id, (path, file));
        Ok(id)
    }

    pub fn append(&self, id: u32, chunk: &[u8]) -> Result<(), String> {
        if chunk.len() > MAX_CHUNK {
            return Err("invalid_attachment".into());
        }
        let mut open = self.open.lock().map_err(|_| "attachment_not_saved")?;
        let (_, file) = open.1.get_mut(&id).ok_or("invalid_attachment")?;
        file.write_all(chunk)
            .map_err(|_| "attachment_not_saved".into())
    }

    pub fn finish(&self, id: u32, complete: bool) -> Result<(), String> {
        let (path, file) = self
            .open
            .lock()
            .map_err(|_| "attachment_not_saved")?
            .1
            .remove(&id)
            .ok_or("invalid_attachment")?;
        let synced = file.sync_all();
        if complete && synced.is_ok() {
            return Ok(());
        }
        let _ = std::fs::remove_file(path);
        if complete {
            Err("attachment_not_saved".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_large_download_is_written_chunk_by_chunk_and_a_failed_one_leaves_nothing() {
        let directory = std::env::temp_dir().join(format!("morse-saves-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let saves = Saves::default();
        let path = directory.join("film.mov");
        let id = saves.start(path.clone()).unwrap();
        saves.append(id, &[1; MAX_CHUNK]).unwrap();
        saves.append(id, &[2, 3]).unwrap();
        assert!(saves.append(id, &vec![0; MAX_CHUNK + 1]).is_err());
        saves.finish(id, true).unwrap();
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written.len(), MAX_CHUNK + 2);
        assert_eq!(&written[MAX_CHUNK..], &[2, 3]);
        assert!(saves.append(id, &[4]).is_err());
        let failed = directory.join("broken.mov");
        let other = saves.start(failed.clone()).unwrap();
        saves.append(other, &[5]).unwrap();
        saves.finish(other, false).unwrap();
        assert!(!failed.exists());
        assert!(saves.finish(other, true).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
