use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Tree(std::path::PathBuf);
impl Tree {
    fn new(name: &str) -> Self {
        let path = std::path::PathBuf::from(std::env::var_os("MORSE_POLICY_FIXTURE_ROOT").unwrap()).join(name);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> std::path::PathBuf { self.0.join(name) }
}
impl Drop for Tree {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}

#[test]
fn selection_does_not_touch_existing_file_until_commit() {
    let tree = Tree::new("destination-existing");
    let path = tree.path("chosen");
    std::fs::write(&path, b"existing user data").unwrap();
    let choice = ChosenDestination::capture(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"existing user data");
    drop(choice);
    assert_eq!(std::fs::read(&path).unwrap(), b"existing user data");
    let mut destination = ChosenDestination::capture(&path).unwrap().open_selected().unwrap();
    std::io::Write::write_all(&mut destination, b"exported").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"exported");
}

#[test]
fn changed_or_replaced_selection_preserves_both_existing_files() {
    let tree = Tree::new("destination-replace");
    let path = tree.path("chosen");
    std::fs::write(&path, b"original").unwrap();
    let choice = ChosenDestination::capture(&path).unwrap();
    std::fs::rename(&path, tree.path("moved")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(choice.open_selected().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert_eq!(std::fs::read(tree.path("moved")).unwrap(), b"original");
    let choice = ChosenDestination::capture(&path).unwrap();
    std::fs::write(&path, b"new edit to preserve").unwrap();
    assert!(choice.open_selected().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"new edit to preserve");
}

#[test]
fn new_selection_never_overwrites_a_later_file_and_follows_original_parent() {
    let tree = Tree::new("destination-new");
    let path = tree.path("chosen");
    let choice = ChosenDestination::capture(&path).unwrap();
    assert!(!path.exists());
    std::fs::write(&path, b"created while chooser pending").unwrap();
    assert!(choice.open_selected().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"created while chooser pending");
    std::fs::create_dir(tree.path("parent")).unwrap();
    let choice = ChosenDestination::capture(&tree.path("parent/new")).unwrap();
    std::fs::rename(tree.path("parent"), tree.path("original-parent")).unwrap();
    std::fs::create_dir(tree.path("parent")).unwrap();
    let mut destination = choice.open_selected().unwrap();
    std::io::Write::write_all(&mut destination, b"bound to native parent").unwrap();
    assert!(!tree.path("parent/new").exists());
    assert_eq!(std::fs::read(tree.path("original-parent/new")).unwrap(), b"bound to native parent");
    assert_eq!(destination.file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn native_destination_refuses_links_directories_and_special_files() {
    let tree = Tree::new("destination-special");
    let target = tree.path("target");
    std::fs::write(&target, b"preserved").unwrap();
    symlink(&target, tree.path("link")).unwrap();
    assert!(ChosenDestination::capture(&tree.path("link")).is_err());
    std::fs::hard_link(&target, tree.path("hardlink")).unwrap();
    assert!(ChosenDestination::capture(&target).is_err());
    std::fs::create_dir(tree.path("directory")).unwrap();
    assert!(ChosenDestination::capture(&tree.path("directory")).is_err());
    let fifo = CString::new(tree.path("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(ChosenDestination::capture(&tree.path("fifo")).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"preserved");
}

struct AccessLifetime(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl crate::desktop_lock::private_files::NativeFileAccess for AccessLifetime {}
impl Drop for AccessLifetime { fn drop(&mut self) { self.0.fetch_add(1,std::sync::atomic::Ordering::SeqCst); } }
#[test]
fn native_url_access_survives_destination_open_until_final_write_owner_drops() {
    use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
    for existing in [false,true] {
        let tree=Tree::new(if existing { "access-existing" } else { "access-new" });let path=tree.path("selected");if existing { std::fs::write(&path,b"previous").unwrap(); }
        let ended=Arc::new(AtomicUsize::new(0));let access=Arc::new(AccessLifetime(ended.clone()));
        let selected=ChosenDestination::capture_selected(&path,access.clone()).unwrap();drop(access);assert_eq!(ended.load(Ordering::SeqCst),0);
        let mut file=selected.open_selected().unwrap();assert_eq!(ended.load(Ordering::SeqCst),0);
        std::io::Write::write_all(&mut file,b"exported").unwrap();file.sync_all().unwrap();assert_eq!(ended.load(Ordering::SeqCst),0);drop(file);
        assert_eq!(ended.load(Ordering::SeqCst),1);assert_eq!(std::fs::read(path).unwrap(),b"exported");
    }
}
