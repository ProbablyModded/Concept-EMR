use serde::Deserialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Sqlite, SqliteConnection, Transaction};
use std::time::Duration;
use tauri::Manager;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetCodeToConsume {
    pub id: i64,
    pub username: String,
    pub code_hash: String,
    pub now: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedAccountMigration {
    pub username: String,
    pub expected_password_hash: String,
    pub new_password_hash: String,
    pub expected_key_envelope: Option<String>,
    pub key_envelope: String,
    pub expected_state_key: Option<String>,
    pub expected_state_value: Option<String>,
    pub require_main_state_absent: bool,
    pub backup_state_key: Option<String>,
    pub backup_state_value: Option<String>,
    pub replacement_main_state: Option<String>,
    pub reset_code: Option<ResetCodeToConsume>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportImport {
    pub username: String,
    pub current_password_hash: String,
    pub key_envelope: String,
    pub statements: Vec<String>,
    pub expected_imported_state: Option<String>,
    pub replacement_main_state: Option<String>,
    pub legacy_backup_state_key: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportInspection {
    pub account_found: bool,
    pub main_state: Option<String>,
}

fn validate_export_statements(statements: &[String]) -> Result<(), String> {
    if statements.is_empty() {
        return Err("The database export contains no SQL statements.".to_string());
    }
    for statement in statements {
        let normalized = statement.trim_start().to_ascii_uppercase();
        if !(normalized.starts_with("CREATE TABLE ") || normalized.starts_with("INSERT INTO ")) {
            return Err("The database export contains an unsupported SQL statement.".to_string());
        }
    }
    Ok(())
}

async fn run_export_statements(
    connection: &mut SqliteConnection,
    statements: &[String],
) -> Result<(), String> {
    validate_export_statements(statements)?;
    for statement in statements {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .map_err(|error| format!("The database export could not be read: {error}"))?;
    }
    Ok(())
}

#[tauri::command]
pub async fn inspect_encrypted_database_export(
    statements: Vec<String>,
    username: String,
) -> Result<EncryptedExportInspection, String> {
    let mut connection = SqliteConnection::connect("sqlite::memory:")
        .await
        .map_err(|error| format!("Could not inspect the database export: {error}"))?;
    run_export_statements(&mut connection, &statements).await?;

    let account_found =
        sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&mut connection)
            .await
            .map_err(|error| {
                format!("The database export does not contain a valid account: {error}")
            })?
            .is_some();
    let has_app_state = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='app_state'",
    )
    .fetch_optional(&mut connection)
    .await
    .map_err(|error| format!("Could not inspect the database export state: {error}"))?
    .is_some();
    let main_state = if has_app_state {
        sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
            .fetch_optional(&mut connection)
            .await
            .map_err(|error| format!("Could not inspect the exported client data: {error}"))?
    } else {
        None
    };

    connection.close().await.ok();
    Ok(EncryptedExportInspection {
        account_found,
        main_state,
    })
}

async fn replace_export_in_transaction(
    connection: &mut SqliteConnection,
    import: EncryptedExportImport,
) -> Result<(), String> {
    validate_export_statements(&import.statements)?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| format!("Could not begin the database restore: {error}"))?;

    let current_hash =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE username = ?")
            .bind(&import.username)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| {
                format!("Could not verify the current account before restore: {error}")
            })?;
    if current_hash.as_deref() != Some(import.current_password_hash.as_str()) {
        return Err(
            "The account changed before restore. The database was not changed.".to_string(),
        );
    }
    let current_envelope = sqlx::query_scalar::<_, String>(
        "SELECT value FROM app_state WHERE key = 'main_key_envelope'",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| format!("Could not verify the current database key: {error}"))?;
    if current_envelope.as_deref() != Some(import.key_envelope.as_str()) {
        return Err(
            "The database key changed before restore. The database was not changed.".to_string(),
        );
    }

    let tables = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|error| format!("Could not prepare the database restore: {error}"))?;
    for table in tables {
        let quoted_table = table.replace('"', "\"\"");
        sqlx::query(&format!("DROP TABLE IF EXISTS \"{quoted_table}\""))
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not replace the existing database tables: {error}"))?;
    }
    for statement in &import.statements {
        sqlx::query(statement)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not restore the database export: {error}"))?;
    }

    let account_found =
        sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE username = ?")
            .bind(&import.username)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| format!("The export does not contain a valid account: {error}"))?
            .is_some();
    if !account_found {
        return Err(
            "The export does not contain the signed-in account. The database was not changed."
                .to_string(),
        );
    }
    sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
        .bind(&import.current_password_hash)
        .bind(&import.username)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("Could not preserve the signed-in account: {error}"))?;

    let imported_state =
        sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| format!("Could not verify the restored client data: {error}"))?;
    if imported_state != import.expected_imported_state {
        return Err(
            "The export contents changed during restore. The database was not changed.".to_string(),
        );
    }

    if let (Some(backup_key), Some(backup_value)) = (
        import.legacy_backup_state_key.as_deref(),
        import.expected_imported_state.as_deref(),
    ) {
        sqlx::query("INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING")
            .bind(backup_key)
            .bind(backup_value)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not preserve the restored legacy data: {error}"))?;
        let preserved =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = ?")
                .bind(backup_key)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| format!("Could not verify the restored legacy data: {error}"))?;
        if preserved.as_deref() != Some(backup_value) {
            return Err(
                "The restored legacy data could not be preserved. The database was not changed."
                    .to_string(),
            );
        }
    }

    if let Some(replacement_state) = import.replacement_main_state.as_deref() {
        let state_envelope: serde_json::Value = serde_json::from_str(replacement_state)
            .map_err(|_| "The restored encrypted state is malformed.".to_string())?;
        if state_envelope
            .get("version")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
            || state_envelope
                .get("algorithm")
                .and_then(serde_json::Value::as_str)
                != Some("AES-256-GCM")
        {
            return Err("The restored encrypted state uses an unsupported format.".to_string());
        }
        sqlx::query("INSERT INTO app_state (key, value) VALUES ('main_state', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(replacement_state)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not secure the restored client data: {error}"))?;
    } else if import.expected_imported_state.is_some() {
        return Err("The restored client data was not encrypted with the current key. The database was not changed.".to_string());
    }

    sqlx::query("INSERT INTO app_state (key, value) VALUES ('main_key_envelope', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(&import.key_envelope)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("Could not preserve the database key after restore: {error}"))?;
    let stored_state =
        sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| format!("Could not verify the restored state: {error}"))?;
    if stored_state != import.replacement_main_state {
        return Err(
            "The restored encrypted data could not be verified. The database was not changed."
                .to_string(),
        );
    }
    let stored_envelope = sqlx::query_scalar::<_, String>(
        "SELECT value FROM app_state WHERE key = 'main_key_envelope'",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| format!("Could not verify the database key after restore: {error}"))?;
    if stored_envelope.as_deref() != Some(import.key_envelope.as_str()) {
        return Err(
            "The database key could not be verified after restore. The database was not changed."
                .to_string(),
        );
    }

    transaction
        .commit()
        .await
        .map_err(|error| format!("Could not finish the database restore: {error}"))
}

#[tauri::command]
pub async fn restore_encrypted_database_export(
    app: tauri::AppHandle,
    import: EncryptedExportImport,
) -> Result<(), String> {
    let database_path = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("Could not locate the SmartEMR database: {error}"))?
        .join("client_records.db");
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(false)
        .foreign_keys(false)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| format!("Could not open the SmartEMR database for restore: {error}"))?;
    let result = replace_export_in_transaction(&mut connection, import).await;
    connection.close().await.ok();
    result
}

async fn read_state_value(
    transaction: &mut Transaction<'_, Sqlite>,
    key: &str,
) -> Result<Option<String>, String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = ?")
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| format!("Could not verify encrypted database state: {error}"))
}

async fn commit_migration(
    connection: &mut SqliteConnection,
    migration: EncryptedAccountMigration,
) -> Result<(), String> {
    if migration.username.trim().is_empty()
        || migration.key_envelope.trim().is_empty()
        || migration.new_password_hash.trim().is_empty()
    {
        return Err("Encrypted account migration data is incomplete.".to_string());
    }
    if !crate::crypto::is_supported_password_hash(&migration.new_password_hash) {
        return Err(
            "The new account password hash is not in the supported secure format.".to_string(),
        );
    }
    let envelope: serde_json::Value = serde_json::from_str(&migration.key_envelope)
        .map_err(|_| "The database key envelope is malformed.".to_string())?;
    if envelope.get("version").and_then(serde_json::Value::as_u64) != Some(2)
        || envelope
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            != Some("AES-256-GCM")
        || !envelope
            .get("dataKeyCheck")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|check| {
                check.len() == 64 && check.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || !envelope
            .get("passwordWrap")
            .is_some_and(serde_json::Value::is_object)
        || !envelope
            .get("recoveryWrap")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("The database key envelope is incomplete or unsupported.".to_string());
    }
    if let Some(state) = migration.replacement_main_state.as_deref() {
        let state_envelope: serde_json::Value = serde_json::from_str(state)
            .map_err(|_| "The encrypted database state is malformed.".to_string())?;
        if state_envelope
            .get("version")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
            || state_envelope
                .get("algorithm")
                .and_then(serde_json::Value::as_str)
                != Some("AES-256-GCM")
        {
            return Err("The encrypted database state uses an unsupported format.".to_string());
        }
    }
    if migration
        .reset_code
        .as_ref()
        .is_some_and(|code| code.username != migration.username)
    {
        return Err("The password reset code belongs to a different account.".to_string());
    }

    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| format!("Could not begin the database migration: {error}"))?;

    let current_key_envelope = read_state_value(&mut transaction, "main_key_envelope").await?;
    if current_key_envelope.as_deref() != migration.expected_key_envelope.as_deref() {
        return Err(
            "The database key envelope changed during migration. No database changes were saved."
                .to_string(),
        );
    }

    let current_password_hash =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE username = ?")
            .bind(&migration.username)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| format!("Could not verify the account before migration: {error}"))?;
    if current_password_hash.as_deref() != Some(migration.expected_password_hash.as_str()) {
        return Err(
            "The account changed during migration. No database changes were saved.".to_string(),
        );
    }

    match (
        migration.expected_state_key.as_deref(),
        migration.expected_state_value.as_deref(),
    ) {
        (Some(key), Some(expected_value)) => {
            let current_value = read_state_value(&mut transaction, key).await?;
            if current_value.as_deref() != Some(expected_value) {
                return Err(
                    "The encrypted state changed during migration. No database changes were saved."
                        .to_string(),
                );
            }
        }
        (None, None) if migration.require_main_state_absent => {
            if read_state_value(&mut transaction, "main_state")
                .await?
                .is_some()
            {
                return Err(
                    "A database state appeared during migration. No database changes were saved."
                        .to_string(),
                );
            }
        }
        (None, None) => {}
        _ => return Err("The database migration state check is incomplete.".to_string()),
    }

    match (
        migration.backup_state_key.as_deref(),
        migration.backup_state_value.as_deref(),
    ) {
        (Some(key), Some(value)) => {
            sqlx::query(
                "INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not preserve the original encrypted state: {error}"))?;
            if read_state_value(&mut transaction, key).await?.as_deref() != Some(value) {
                return Err("The original encrypted state could not be preserved. No database changes were saved.".to_string());
            }
        }
        (None, None) => {}
        _ => return Err("The original database state backup is incomplete.".to_string()),
    }

    if let Some(encrypted_state) = migration.replacement_main_state.as_deref() {
        sqlx::query(
            "INSERT INTO app_state (key, value) VALUES ('main_state', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(encrypted_state)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("Could not save the migrated encrypted state: {error}"))?;
        if read_state_value(&mut transaction, "main_state")
            .await?
            .as_deref()
            != Some(encrypted_state)
        {
            return Err("The migrated encrypted state could not be verified. No database changes were saved.".to_string());
        }
    }

    sqlx::query(
        "INSERT INTO app_state (key, value) VALUES ('main_key_envelope', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&migration.key_envelope)
    .execute(&mut *transaction)
    .await
    .map_err(|error| format!("Could not save the database key envelope: {error}"))?;
    if read_state_value(&mut transaction, "main_key_envelope")
        .await?
        .as_deref()
        != Some(migration.key_envelope.as_str())
    {
        return Err(
            "The database key envelope could not be verified. No database changes were saved."
                .to_string(),
        );
    }

    let updated =
        sqlx::query("UPDATE users SET password_hash = ? WHERE username = ? AND password_hash = ?")
            .bind(&migration.new_password_hash)
            .bind(&migration.username)
            .bind(&migration.expected_password_hash)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not update the account password: {error}"))?;
    if updated.rows_affected() != 1 {
        return Err(
            "The account password could not be verified. No database changes were saved."
                .to_string(),
        );
    }

    if let Some(reset_code) = &migration.reset_code {
        let consumed = sqlx::query(
            "UPDATE password_reset_codes SET used = 1 WHERE id = ? AND username = ? AND code_hash = ? AND used = 0 AND expires_at >= ? AND attempts < 5",
        )
        .bind(reset_code.id)
        .bind(&reset_code.username)
        .bind(&reset_code.code_hash)
        .bind(reset_code.now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("Could not confirm the password reset code: {error}"))?;
        if consumed.rows_affected() != 1 {
            return Err("The password reset code expired or was already used. No database changes were saved.".to_string());
        }
        sqlx::query("DELETE FROM password_reset_codes WHERE username = ? AND id != ?")
            .bind(&reset_code.username)
            .bind(reset_code.id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("Could not clear older password reset codes: {error}"))?;
    }

    transaction
        .commit()
        .await
        .map_err(|error| format!("Could not finish the database migration: {error}"))
}

#[tauri::command]
pub async fn commit_encrypted_account_migration(
    app: tauri::AppHandle,
    migration: EncryptedAccountMigration,
) -> Result<(), String> {
    let database_path = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("Could not locate the SmartEMR database: {error}"))?
        .join("client_records.db");
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| format!("Could not open the SmartEMR database for migration: {error}"))?;
    let result = commit_migration(&mut connection, migration).await;
    connection.close().await.ok();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn test_connection() -> SqliteConnection {
        SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should open")
    }

    async fn create_test_schema(connection: &mut SqliteConnection) {
        sqlx::query("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE password_reset_codes (id INTEGER PRIMARY KEY, username TEXT, code_hash TEXT, expires_at INTEGER, attempts INTEGER, used INTEGER)")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users (username, password_hash) VALUES ('test-user', 'legacy-hash')",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO app_state (key, value) VALUES ('main_state', 'legacy-ciphertext')",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn commits_preserve_legacy_state_and_write_v2_state_as_one_unit() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let new_password_hash =
            crate::crypto::hash_account_password("new secure password".to_string())
                .expect("the test password hash should be valid");
        let migration = EncryptedAccountMigration {
            username: "test-user".to_string(),
            expected_password_hash: "legacy-hash".to_string(),
            new_password_hash: new_password_hash.clone(),
            expected_key_envelope: None,
            key_envelope:
                r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"0000000000000000000000000000000000000000000000000000000000000000","passwordWrap":{},"recoveryWrap":{}}"#
                    .to_string(),
            expected_state_key: Some("main_state".to_string()),
            expected_state_value: Some("legacy-ciphertext".to_string()),
            require_main_state_absent: false,
            backup_state_key: Some("main_state_legacy_v1".to_string()),
            backup_state_value: Some("legacy-ciphertext".to_string()),
            replacement_main_state: Some(r#"{"version":2,"algorithm":"AES-256-GCM"}"#.to_string()),
            reset_code: None,
        };

        commit_migration(&mut connection, migration)
            .await
            .expect("migration should commit");

        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let legacy_state = sqlx::query_scalar::<_, String>(
            "SELECT value FROM app_state WHERE key = 'main_state_legacy_v1'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(password_hash, new_password_hash);
        assert_eq!(current_state, r#"{"version":2,"algorithm":"AES-256-GCM"}"#);
        assert_eq!(legacy_state, "legacy-ciphertext");
    }

    #[tokio::test]
    async fn rejects_malformed_key_binding_without_changing_account_or_state() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let migration = EncryptedAccountMigration {
            username: "test-user".to_string(),
            expected_password_hash: "legacy-hash".to_string(),
            new_password_hash: crate::crypto::hash_account_password(
                "new secure password".to_string(),
            )
            .expect("the test password hash should be valid"),
            expected_key_envelope: None,
            key_envelope: r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"bad","passwordWrap":{},"recoveryWrap":{}}"#.to_string(),
            expected_state_key: Some("main_state".to_string()),
            expected_state_value: Some("legacy-ciphertext".to_string()),
            require_main_state_absent: false,
            backup_state_key: None,
            backup_state_value: None,
            replacement_main_state: None,
            reset_code: None,
        };

        assert!(commit_migration(&mut connection, migration).await.is_err());
        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let envelope = sqlx::query_scalar::<_, String>(
            "SELECT value FROM app_state WHERE key = 'main_key_envelope'",
        )
        .fetch_optional(&mut connection)
        .await
        .unwrap();
        assert_eq!(password_hash, "legacy-hash");
        assert_eq!(current_state, "legacy-ciphertext");
        assert_eq!(envelope, None);
    }

    #[tokio::test]
    async fn rejects_migration_if_the_key_envelope_changed_after_preflight() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let original_envelope = r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"0000000000000000000000000000000000000000000000000000000000000000","passwordWrap":{},"recoveryWrap":{}}"#;
        sqlx::query("INSERT INTO app_state (key, value) VALUES ('main_key_envelope', ?)")
            .bind(original_envelope)
            .execute(&mut connection)
            .await
            .unwrap();
        let migration = EncryptedAccountMigration {
            username: "test-user".to_string(),
            expected_password_hash: "legacy-hash".to_string(),
            new_password_hash: crate::crypto::hash_account_password(
                "new secure password".to_string(),
            )
            .expect("the test password hash should be valid"),
            expected_key_envelope: Some("stale-key-envelope".to_string()),
            key_envelope: original_envelope.to_string(),
            expected_state_key: Some("main_state".to_string()),
            expected_state_value: Some("legacy-ciphertext".to_string()),
            require_main_state_absent: false,
            backup_state_key: None,
            backup_state_value: None,
            replacement_main_state: None,
            reset_code: None,
        };

        assert!(commit_migration(&mut connection, migration).await.is_err());
        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let stored_envelope = sqlx::query_scalar::<_, String>(
            "SELECT value FROM app_state WHERE key = 'main_key_envelope'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(password_hash, "legacy-hash");
        assert_eq!(stored_envelope, original_envelope);
        assert_eq!(current_state, "legacy-ciphertext");
    }

    #[tokio::test]
    async fn failed_reset_rolls_back_password_state_and_code_consumption() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let new_password_hash =
            crate::crypto::hash_account_password("new secure password".to_string())
                .expect("the test password hash should be valid");
        sqlx::query("INSERT INTO password_reset_codes (id, username, code_hash, expires_at, attempts, used) VALUES (7, 'test-user', 'reset-hash', 9999999999999, 0, 0)")
            .execute(&mut connection)
            .await
            .unwrap();
        let migration = EncryptedAccountMigration {
            username: "test-user".to_string(),
            expected_password_hash: "legacy-hash".to_string(),
            new_password_hash,
            expected_key_envelope: None,
            key_envelope:
                r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"0000000000000000000000000000000000000000000000000000000000000000","passwordWrap":{},"recoveryWrap":{}}"#
                    .to_string(),
            expected_state_key: Some("main_state".to_string()),
            expected_state_value: Some("legacy-ciphertext".to_string()),
            require_main_state_absent: false,
            backup_state_key: Some("main_state_legacy_v1".to_string()),
            backup_state_value: Some("legacy-ciphertext".to_string()),
            replacement_main_state: Some(r#"{"version":2,"algorithm":"AES-256-GCM"}"#.to_string()),
            reset_code: Some(ResetCodeToConsume {
                id: 7,
                username: "test-user".to_string(),
                code_hash: "wrong-hash".to_string(),
                now: 1,
            }),
        };

        assert!(commit_migration(&mut connection, migration).await.is_err());
        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let used =
            sqlx::query_scalar::<_, i64>("SELECT used FROM password_reset_codes WHERE id = 7")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(password_hash, "legacy-hash");
        assert_eq!(current_state, "legacy-ciphertext");
        assert_eq!(used, 0);
    }

    #[tokio::test]
    async fn encrypted_export_restore_rekeys_legacy_state_and_preserves_login() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let key_envelope = r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"0000000000000000000000000000000000000000000000000000000000000000","passwordWrap":{},"recoveryWrap":{}}"#;
        sqlx::query("INSERT INTO app_state (key, value) VALUES ('main_key_envelope', ?)")
            .bind(key_envelope)
            .execute(&mut connection)
            .await
            .unwrap();
        let replacement_state =
            r#"{"version":2,"algorithm":"AES-256-GCM","nonce":"n","ciphertext":"c"}"#;
        let import = EncryptedExportImport {
            username: "test-user".to_string(),
            current_password_hash: "legacy-hash".to_string(),
            key_envelope: key_envelope.to_string(),
            statements: vec![
                "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)"
                    .to_string(),
                "INSERT INTO users (username, password_hash) VALUES ('test-user', 'backup-hash')"
                    .to_string(),
                "CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)".to_string(),
                "INSERT INTO app_state (key, value) VALUES ('main_state', 'legacy-ciphertext')"
                    .to_string(),
            ],
            expected_imported_state: Some("legacy-ciphertext".to_string()),
            replacement_main_state: Some(replacement_state.to_string()),
            legacy_backup_state_key: Some("main_state_legacy_v1_import_test".to_string()),
        };

        replace_export_in_transaction(&mut connection, import)
            .await
            .expect("restore should commit");

        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let backup_state = sqlx::query_scalar::<_, String>(
            "SELECT value FROM app_state WHERE key = 'main_state_legacy_v1_import_test'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(password_hash, "legacy-hash");
        assert_eq!(current_state, replacement_state);
        assert_eq!(backup_state, "legacy-ciphertext");
    }

    #[tokio::test]
    async fn failed_export_restore_leaves_live_database_unchanged() {
        let mut connection = test_connection().await;
        create_test_schema(&mut connection).await;
        let key_envelope = r#"{"version":2,"algorithm":"AES-256-GCM","dataKeyCheck":"0000000000000000000000000000000000000000000000000000000000000000","passwordWrap":{},"recoveryWrap":{}}"#;
        sqlx::query("INSERT INTO app_state (key, value) VALUES ('main_key_envelope', ?)")
            .bind(key_envelope)
            .execute(&mut connection)
            .await
            .unwrap();
        let import = EncryptedExportImport {
            username: "test-user".to_string(),
            current_password_hash: "legacy-hash".to_string(),
            key_envelope: key_envelope.to_string(),
            statements: vec![
                "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)"
                    .to_string(),
                "INSERT INTO users (username, password_hash) VALUES ('test-user', 'backup-hash')"
                    .to_string(),
                "CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)".to_string(),
                "INSERT INTO app_state (key, value) VALUES ('main_state', 'other-ciphertext')"
                    .to_string(),
            ],
            expected_imported_state: Some("expected-ciphertext".to_string()),
            replacement_main_state: Some(r#"{"version":2,"algorithm":"AES-256-GCM"}"#.to_string()),
            legacy_backup_state_key: None,
        };

        assert!(replace_export_in_transaction(&mut connection, import)
            .await
            .is_err());
        let password_hash = sqlx::query_scalar::<_, String>(
            "SELECT password_hash FROM users WHERE username = 'test-user'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let current_state =
            sqlx::query_scalar::<_, String>("SELECT value FROM app_state WHERE key = 'main_state'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(password_hash, "legacy-hash");
        assert_eq!(current_state, "legacy-ciphertext");
    }
}
