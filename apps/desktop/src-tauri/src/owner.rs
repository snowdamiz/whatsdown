// App lock on the desktop (apps/mobile/src/LockGate.tsx): the Mac's own owner
// check, Touch ID or the login password, through LocalAuthentication. Other
// desktops have no owner check wired in, so they don't offer the lock.
// The web view's side is apps/mobile/modules/mesh-messenger/lock.web.ts.

#[cfg(target_os = "macos")]
mod platform {
    use block2::RcBlock;
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2_foundation::NSString;
    use std::sync::mpsc;

    #[link(name = "LocalAuthentication", kind = "framework")]
    extern "C" {}

    // LAPolicyDeviceOwnerAuthentication: Touch ID, a paired watch, or the password.
    const DEVICE_OWNER: isize = 2;

    fn context() -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"LAContext")?;
        unsafe { msg_send![class, new] }
    }

    pub fn available() -> bool {
        let Some(context) = context() else {
            return false;
        };
        let mut error: *mut AnyObject = std::ptr::null_mut();
        let able: Bool =
            unsafe { msg_send![&*context, canEvaluatePolicy: DEVICE_OWNER, error: &mut error] };
        able.as_bool()
    }

    // The reply arrives on LocalAuthentication's own queue; this command runs off
    // the main thread, so it waits for it.
    pub fn authenticate(reason: &str) -> bool {
        if !available() {
            // No owner check left to make (as on the phones).
            return true;
        }
        let Some(context) = context() else {
            return false;
        };
        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |granted: Bool, _error: *mut AnyObject| {
            let _ = sender.send(granted.as_bool());
        });
        let reason = NSString::from_str(reason);
        unsafe {
            let _: () = msg_send![&*context, evaluatePolicy: DEVICE_OWNER, localizedReason: &*reason, reply: &*reply];
        }
        receiver.recv().unwrap_or(false)
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> bool {
        true
    }
}

#[tauri::command(async)]
pub fn lock_available() -> bool {
    platform::available()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    // LocalAuthentication answers without asking anyone; a wrong selector or
    // argument type would panic here (objc2 checks encodings in debug builds).
    #[test]
    fn the_macs_owner_check_answers_whether_it_can_ask() {
        let _ = super::platform::available();
    }
}

#[tauri::command(async)]
pub fn lock_authenticate(reason: String) -> bool {
    platform::authenticate(&reason)
}
