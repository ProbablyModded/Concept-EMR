const DEVICE_KEY_SERVICE_NAME: &str = "com.clientrecords.tauriapp.data-key.v1";

fn normalize_username(username: &str) -> Result<String, String> {
    let normalized = username.trim();
    if normalized.is_empty() {
        return Err("Username is required for local key recovery.".to_string());
    }
    Ok(normalized.to_string())
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{normalize_username, DEVICE_KEY_SERVICE_NAME};
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        PasswordOptions,
    };

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    fn format_error(action: &str, error: security_framework::base::Error) -> String {
        match error.code() {
            ERR_SEC_ITEM_NOT_FOUND => {
                "No local recovery key is saved for this account on this Mac.".to_string()
            }
            _ => match error.message() {
                Some(message) if !message.trim().is_empty() => {
                    format!("Failed to {action}: {message}")
                }
                _ => format!("Failed to {action}. Security status code: {}", error.code()),
            },
        }
    }

    pub fn store_device_data_key(username: &str, secret: &str) -> Result<(), String> {
        let account = normalize_username(username)?;
        if secret.trim().is_empty() {
            return Err("Local recovery key is empty.".to_string());
        }
        let mut options = PasswordOptions::new_generic_password(DEVICE_KEY_SERVICE_NAME, &account);
        options.set_access_synchronized(Some(false));
        options.set_label("SmartEMR Local Data Recovery Key");
        options.set_comment(
            "Unlocks the encrypted SmartEMR database on this Mac after verified account recovery.",
        );
        set_generic_password_options(secret.as_bytes(), options)
            .map_err(|error| format_error("save the local recovery key", error))
    }

    pub fn read_device_data_key(username: &str) -> Result<String, String> {
        let account = normalize_username(username)?;
        let mut options = PasswordOptions::new_generic_password(DEVICE_KEY_SERVICE_NAME, &account);
        options.set_access_synchronized(Some(false));
        let bytes = generic_password(options)
            .map_err(|error| format_error("read the local recovery key", error))?;
        String::from_utf8(bytes).map_err(|_| "The saved local recovery key is invalid.".to_string())
    }

    pub fn remove_device_data_key(username: &str) -> Result<(), String> {
        let account = normalize_username(username)?;
        let mut options = PasswordOptions::new_generic_password(DEVICE_KEY_SERVICE_NAME, &account);
        options.set_access_synchronized(Some(false));
        match delete_generic_password_options(options) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(format_error("remove the local recovery key", error)),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod macos {
    pub fn store_device_data_key(_username: &str, _secret: &str) -> Result<(), String> {
        Err("Local Keychain recovery is available only in the macOS desktop app.".to_string())
    }
    pub fn read_device_data_key(_username: &str) -> Result<String, String> {
        Err("Local Keychain recovery is available only in the macOS desktop app.".to_string())
    }
    pub fn remove_device_data_key(_username: &str) -> Result<(), String> {
        Ok(())
    }
}

#[tauri::command]
pub fn store_device_data_key(username: String, secret: String) -> Result<(), String> {
    macos::store_device_data_key(&username, &secret)
}

#[tauri::command]
pub fn read_device_data_key(username: String) -> Result<String, String> {
    macos::read_device_data_key(&username)
}

#[tauri::command]
pub fn remove_device_data_key(username: String) -> Result<(), String> {
    macos::remove_device_data_key(&username)
}
