import Database from '@tauri-apps/plugin-sql';
import CryptoJS from 'crypto-js';

let db = null;
let encryptionKey = null;
let encryptionMode = 'legacy';
let currentUser = null;
let lastAuthError = '';
let pendingRecoveryCode = '';
const DATA_KEY_ENVELOPE_KEY = 'main_key_envelope';
const LEGACY_STATE_BACKUP_KEY = 'main_state_legacy_v1';
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const CODE_RESEND_COOLDOWN_MS = 60 * 1000;
const CODE_MAX_PER_HOUR = 5;

const invokeTauriCommand = async (command, args) => {
    const invoke = window?.__TAURI__?.core?.invoke;
    if (typeof invoke !== 'function') {
        throw new Error('Desktop runtime is required for secure credential operations.');
    }
    return invoke(command, args);
};

const deriveEncryptionKey = (username, password) => CryptoJS.SHA256(`${password}${username}`).toString();
const encryptStateString = (state, key) => CryptoJS.AES.encrypt(JSON.stringify(state), key).toString();
const upsertAppState = (database, key, value) => database.execute(
    'INSERT INTO app_state (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = $2',
    [key, value]
);

function isArgonPasswordHash(passwordHash) {
    return typeof passwordHash === 'string' && passwordHash.startsWith('$argon2id$');
}

function matchesDataKeyBinding(dataKey, username, envelope) {
    if (!dataKey || !username || typeof envelope?.dataKeyCheck !== 'string') return false;
    const expected = CryptoJS.SHA256(`smartemr/data-key-check/v1/${username}/${dataKey}`).toString();
    return expected === envelope.dataKeyCheck;
}

async function hashPassword(password) {
    return invokeTauriCommand('hash_account_password', { password });
}

async function verifyPassword(password, passwordHash) {
    if (isArgonPasswordHash(passwordHash)) {
        return invokeTauriCommand('verify_account_password', { password, passwordHash });
    }
    return CryptoJS.SHA256(password || '').toString() === passwordHash;
}

async function readStateRow(database, key = 'main_state') {
    const rows = await database.select('SELECT value FROM app_state WHERE key = $1', [key]);
    return rows?.length ? rows[0].value : null;
}

async function readKeyEnvelopeRecord(database) {
    const raw = await readStateRow(database, DATA_KEY_ENVELOPE_KEY);
    if (!raw) return null;
    try {
        const envelope = JSON.parse(raw);
        if (envelope?.version !== 2
            || envelope.algorithm !== 'AES-256-GCM'
            || !/^[a-f0-9]{64}$/.test(envelope.dataKeyCheck || '')
            || !envelope.passwordWrap
            || !envelope.recoveryWrap) {
            throw new Error('The database key envelope is incomplete.');
        }
        return { raw, envelope };
    } catch (error) {
        throw new Error(error?.message || 'The database key envelope is damaged.');
    }
}

async function readKeyEnvelope(database) {
    return (await readKeyEnvelopeRecord(database))?.envelope ?? null;
}

async function getDataKeyFromPassword(password, envelope) {
    return invokeTauriCommand('unwrap_data_key_with_password', {
        password,
        wrappedKeyJson: JSON.stringify(envelope.passwordWrap)
    });
}

async function getDataKeyFromRecoveryCode(recoveryCode, envelope) {
    return invokeTauriCommand('unwrap_data_key_with_recovery_key', {
        recoveryKey: recoveryCode,
        wrappedKeyJson: JSON.stringify(envelope.recoveryWrap)
    });
}

async function wrapDataKeyWithPassword(password, dataKey) {
    const wrapped = await invokeTauriCommand('wrap_data_key_with_password', {
        password,
        dataKey
    });
    return JSON.parse(wrapped);
}

async function wrapDataKeyWithRecoveryCode(recoveryCode, dataKey) {
    const wrapped = await invokeTauriCommand('wrap_data_key_with_recovery_key', {
        recoveryKey: recoveryCode,
        dataKey
    });
    return JSON.parse(wrapped);
}

async function encryptV2State(stateText, dataKey, username) {
    return invokeTauriCommand('encrypt_application_state', {
        dataKey,
        account: username,
        plaintext: stateText
    });
}

async function decryptV2State(encryptedState, dataKey, username) {
    return invokeTauriCommand('decrypt_application_state', {
        dataKey,
        account: username,
        encryptedPayload: encryptedState
    });
}

function isV2EncryptedState(encryptedState) {
    try {
        const envelope = JSON.parse(encryptedState);
        return envelope?.version === 2 && envelope?.algorithm === 'AES-256-GCM';
    } catch (_error) {
        return false;
    }
}

function decryptLegacyState(encryptedState, key) {
    const decryptedBytes = CryptoJS.AES.decrypt(encryptedState, key);
    const plaintext = decryptedBytes.toString(CryptoJS.enc.Utf8);
    if (!plaintext) throw new Error('The saved database could not be decrypted with this key.');
    JSON.parse(plaintext);
    return plaintext;
}

async function storeLocalDataKey(username, dataKey) {
    try {
        await invokeTauriCommand('store_device_data_key', { username, secret: dataKey });
        return true;
    } catch (error) {
        console.warn('Local device recovery key could not be saved:', error);
        return false;
    }
}

async function makeV2Envelope(username, password, dataKey, recoveryCode, recoveryKeyAcknowledged = false, legacyBackupKey = '') {
    const envelope = {
        version: 2,
        algorithm: 'AES-256-GCM',
        dataKeyCheck: CryptoJS.SHA256(`smartemr/data-key-check/v1/${username}/${dataKey}`).toString(),
        passwordWrap: await wrapDataKeyWithPassword(password, dataKey),
        recoveryWrap: await wrapDataKeyWithRecoveryCode(recoveryCode, dataKey),
        recoveryKeyAcknowledged: !!recoveryKeyAcknowledged
    };
    if (legacyBackupKey) {
        envelope.legacyBackupKeyEnvelope = await encryptV2State(legacyBackupKey, dataKey, username);
    }
    return envelope;
}

async function decryptLegacyOrFail(encryptedState, key) {
    try {
        return decryptLegacyState(encryptedState, key);
    } catch (_error) {
        throw new Error('The password was accepted, but the existing database could not be unlocked. Try Touch ID or restore a backup. No data was changed.');
    }
}

async function commitEncryptedAccountMigration(migration) {
    await invokeTauriCommand('commit_encrypted_account_migration', { migration });
}

async function migrateLegacyAccount(database, username, password, legacyKey, passwordHash, resetCode = null) {
    const currentMainState = await readStateRow(database, 'main_state');
    const existingLegacyBackup = await readStateRow(database, LEGACY_STATE_BACKUP_KEY);
    const legacyEncryptedState = currentMainState ?? existingLegacyBackup;
    const legacyStateKey = currentMainState !== null
        ? 'main_state'
        : (existingLegacyBackup !== null ? LEGACY_STATE_BACKUP_KEY : null);
    const legacyBackupRowKey = !existingLegacyBackup || existingLegacyBackup === legacyEncryptedState
        ? LEGACY_STATE_BACKUP_KEY
        : `${LEGACY_STATE_BACKUP_KEY}_${Date.now()}`;
    let plaintext = null;
    if (legacyEncryptedState) {
        plaintext = await decryptLegacyOrFail(legacyEncryptedState, legacyKey);
    }

    const dataKey = await invokeTauriCommand('generate_data_encryption_key');
    const recoveryCode = await invokeTauriCommand('generate_recovery_key');
    const envelope = await makeV2Envelope(username, password, dataKey, recoveryCode, false, legacyKey);
    if ((await getDataKeyFromPassword(password, envelope)) !== dataKey
        || (await getDataKeyFromRecoveryCode(recoveryCode, envelope)) !== dataKey
        || !matchesDataKeyBinding(dataKey, username, envelope)) {
        throw new Error('Database key recovery verification failed. The original data was not changed.');
    }
    const modernPasswordHash = isArgonPasswordHash(passwordHash) ? passwordHash : await hashPassword(password);
    let encryptedState = null;
    if (plaintext !== null) {
        encryptedState = await encryptV2State(plaintext, dataKey, username);
        const verifiedPlaintext = await decryptV2State(encryptedState, dataKey, username);
        if (verifiedPlaintext !== plaintext) {
            throw new Error('Database migration verification failed. The original data was not changed.');
        }
    }

    if (legacyKey
        && (await decryptV2State(envelope.legacyBackupKeyEnvelope, dataKey, username)) !== legacyKey) {
        throw new Error('Legacy backup recovery verification failed. The original data was not changed.');
    }

    await commitEncryptedAccountMigration({
        username,
        expectedPasswordHash: passwordHash,
        newPasswordHash: modernPasswordHash,
        expectedKeyEnvelope: null,
        keyEnvelope: JSON.stringify(envelope),
        expectedStateKey: legacyStateKey,
        expectedStateValue: legacyEncryptedState,
        requireMainStateAbsent: legacyStateKey === null,
        backupStateKey: legacyEncryptedState !== null
            && (!existingLegacyBackup || existingLegacyBackup !== legacyEncryptedState)
            ? legacyBackupRowKey
            : null,
        backupStateValue: legacyEncryptedState !== null
            && (!existingLegacyBackup || existingLegacyBackup !== legacyEncryptedState)
            ? legacyEncryptedState
            : null,
        replacementMainState: encryptedState,
        resetCode
    });

    const savedEnvelope = await readKeyEnvelope(database);
    const savedHashRows = await database.select('SELECT password_hash FROM users WHERE username = $1', [username]);
    if (!savedEnvelope || !savedHashRows?.length || !(await verifyPassword(password, savedHashRows[0].password_hash))) {
        throw new Error('Database migration verification failed after commit. The original state remains archived.');
    }
    if (encryptedState && (await decryptV2State(await readStateRow(database), dataKey, username)) !== plaintext) {
        throw new Error('Database migration verification failed after commit. The original state remains archived.');
    }

    encryptionKey = dataKey;
    encryptionMode = 'v2';
    currentUser = username;
    pendingRecoveryCode = recoveryCode;
    await storeLocalDataKey(username, dataKey);
}

async function initializeV2Account(database, username, password, expectedPasswordHash, resetCode = null) {
    const dataKey = await invokeTauriCommand('generate_data_encryption_key');
    const recoveryCode = await invokeTauriCommand('generate_recovery_key');
    const envelope = await makeV2Envelope(username, password, dataKey, recoveryCode, false);
    const passwordHash = await hashPassword(password);
    if ((await getDataKeyFromPassword(password, envelope)) !== dataKey
        || (await getDataKeyFromRecoveryCode(recoveryCode, envelope)) !== dataKey
        || !matchesDataKeyBinding(dataKey, username, envelope)
        || !(await verifyPassword(password, passwordHash))) {
        throw new Error('Database key setup verification failed. No account changes were saved.');
    }

    await commitEncryptedAccountMigration({
        username,
        expectedPasswordHash,
        newPasswordHash: passwordHash,
        expectedKeyEnvelope: null,
        keyEnvelope: JSON.stringify(envelope),
        expectedStateKey: null,
        expectedStateValue: null,
        requireMainStateAbsent: true,
        backupStateKey: null,
        backupStateValue: null,
        replacementMainState: null,
        resetCode
    });
    const savedEnvelope = await readKeyEnvelope(database);
    const savedRows = await database.select('SELECT password_hash FROM users WHERE username = $1', [username]);
    if (!savedEnvelope || !savedRows?.length
        || !(await verifyPassword(password, savedRows[0].password_hash))
        || (await getDataKeyFromPassword(password, savedEnvelope)) !== dataKey
        || (await getDataKeyFromRecoveryCode(recoveryCode, savedEnvelope)) !== dataKey) {
        throw new Error('Database key setup verification failed after commit. No account changes were saved.');
    }

    encryptionKey = dataKey;
    encryptionMode = 'v2';
    currentUser = username;
    pendingRecoveryCode = recoveryCode;
    await storeLocalDataKey(username, dataKey);
}

async function openV2Account(database, username, password, envelope) {
    const dataKey = await getDataKeyFromPassword(password, envelope);
    if (!matchesDataKeyBinding(dataKey, username, envelope)) {
        throw new Error('The unwrapped database key does not match this account. No data was changed.');
    }
    const encryptedState = await readStateRow(database, 'main_state');
    if (encryptedState) {
        const plaintext = await decryptV2State(encryptedState, dataKey, username);
        JSON.parse(plaintext);
    }

    encryptionKey = dataKey;
    encryptionMode = 'v2';
    currentUser = username;
    await storeLocalDataKey(username, dataKey);

    if (!envelope.recoveryKeyAcknowledged) {
        const recoveryCode = await invokeTauriCommand('generate_recovery_key');
        const updatedEnvelope = {
            ...envelope,
            recoveryWrap: await wrapDataKeyWithRecoveryCode(recoveryCode, dataKey),
            recoveryKeyAcknowledged: false
        };
        await upsertAppState(database, DATA_KEY_ENVELOPE_KEY, JSON.stringify(updatedEnvelope));
        pendingRecoveryCode = recoveryCode;
    }
}

function validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword) {
    const normalizedHost = (smtpHost || '').trim();
    const normalizedSecurity = (smtpSecurity || '').trim().toLowerCase();

    if (!normalizedHost) {
        return 'SMTP host is required.';
    }

    const parsedPort = Number(smtpPort);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        return 'SMTP port must be a valid port number (1-65535).';
    }

    if (normalizedSecurity !== 'starttls' && normalizedSecurity !== 'tls' && normalizedSecurity !== 'ssl') {
        return 'SMTP security must be STARTTLS, TLS, or SSL.';
    }

    if (!smtpUsername || !smtpFrom || !smtpPassword) {
        return 'SMTP authentication is required (username, from email, and app password).';
    }

    return '';
}

async function enforceCodeRateLimit(database, tableName, normalizedUsername, contextLabel) {
    const now = Date.now();
    const recentRows = await database.select(
        `SELECT created_at FROM ${tableName} WHERE username = $1 ORDER BY created_at DESC LIMIT 1`,
        [normalizedUsername]
    );

    if (recentRows?.length) {
        const lastCreatedAt = Number(recentRows[0].created_at || 0);
        const elapsed = now - lastCreatedAt;
        if (elapsed < CODE_RESEND_COOLDOWN_MS) {
            const waitSeconds = Math.ceil((CODE_RESEND_COOLDOWN_MS - elapsed) / 1000);
            lastAuthError = `Please wait ${waitSeconds}s before requesting another ${contextLabel} code.`;
            return false;
        }
    }

    const hourlyRows = await database.select(
        `SELECT COUNT(*) as count FROM ${tableName} WHERE username = $1 AND created_at >= $2`,
        [normalizedUsername, now - (60 * 60 * 1000)]
    );
    const hourlyCount = Number(hourlyRows?.[0]?.count ?? 0);
    if (hourlyCount >= CODE_MAX_PER_HOUR) {
        lastAuthError = `Too many ${contextLabel} requests. Try again in about an hour.`;
        return false;
    }

    return true;
}

async function ensureSchema(database) {
    await database.execute(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    `);

    const userColumns = await database.select('PRAGMA table_info(users)');
    const existing = new Set((userColumns || []).map(col => col.name));
    const additions = [
        { name: 'email', sql: 'ALTER TABLE users ADD COLUMN email TEXT' },
        { name: 'smtp_host', sql: 'ALTER TABLE users ADD COLUMN smtp_host TEXT' },
        { name: 'smtp_port', sql: 'ALTER TABLE users ADD COLUMN smtp_port INTEGER' },
        { name: 'smtp_security', sql: 'ALTER TABLE users ADD COLUMN smtp_security TEXT' },
        { name: 'smtp_username', sql: 'ALTER TABLE users ADD COLUMN smtp_username TEXT' },
        { name: 'smtp_from', sql: 'ALTER TABLE users ADD COLUMN smtp_from TEXT' },
        { name: 'smtp_password', sql: 'ALTER TABLE users ADD COLUMN smtp_password TEXT' },
        { name: 'recovery_enabled', sql: 'ALTER TABLE users ADD COLUMN recovery_enabled INTEGER DEFAULT 0' },
        { name: 'email_verified', sql: 'ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1' },
        { name: 'email_verified_at', sql: 'ALTER TABLE users ADD COLUMN email_verified_at INTEGER' }
    ];
    for (const item of additions) {
        if (!existing.has(item.name)) {
            await database.execute(item.sql);
        }
    }

    await database.execute(`
        CREATE TABLE IF NOT EXISTS password_reset_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    `);
    await database.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_username ON password_reset_codes(username)');

    await database.execute(`
        CREATE TABLE IF NOT EXISTS email_verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    `);
    await database.execute('CREATE INDEX IF NOT EXISTS idx_email_verify_username ON email_verification_codes(username)');
}

async function sendEmailVerificationCode(database, normalizedUsername) {
    const rows = await database.select(
        'SELECT username, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified FROM users WHERE username = $1',
        [normalizedUsername]
    );

    if (!rows?.length) {
        lastAuthError = 'Account not found.';
        return false;
    }

    const user = rows[0];
    if (Number(user.email_verified) === 1) {
        lastAuthError = 'Email is already verified. You can log in now.';
        return false;
    }

    if (!user.recovery_enabled || !user.email || !user.smtp_host || !user.smtp_port || !user.smtp_username || !user.smtp_from || !user.smtp_password) {
        lastAuthError = 'SMTP recovery settings are required to verify email.';
        return false;
    }

    const rateAllowed = await enforceCodeRateLimit(database, 'email_verification_codes', normalizedUsername, 'verification');
    if (!rateAllowed) {
        return false;
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = CryptoJS.SHA256(`${normalizedUsername}:verify:${code}`).toString();
    const now = Date.now();
    const expiresAt = now + EMAIL_CODE_TTL_MS;

    await database.execute('DELETE FROM email_verification_codes WHERE username = $1 OR expires_at < $2 OR used = 1', [normalizedUsername, now - (24 * 60 * 60 * 1000)]);
    await database.execute(
        'INSERT INTO email_verification_codes (username, code_hash, expires_at, attempts, used, created_at) VALUES ($1, $2, $3, 0, 0, $4)',
        [normalizedUsername, codeHash, expiresAt, now]
    );

    try {
        console.log('[DEBUG] Sending verification email with args:', {
            username: normalizedUsername,
            toEmail: user.email,
            smtpHost: user.smtp_host,
            smtpPort: Number(user.smtp_port),
            smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
            smtpUsername: user.smtp_username,
            smtpPassword: user.smtp_password ? '***' : 'MISSING',
            fromEmail: user.smtp_from,
            code
        });
        await invokeTauriCommand('send_email_verification_email', {
            args: {
                username: normalizedUsername,
                toEmail: user.email,
                smtpHost: user.smtp_host,
                smtpPort: Number(user.smtp_port),
                smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
                smtpUsername: user.smtp_username,
                smtpPassword: user.smtp_password,
                fromEmail: user.smtp_from,
                code
            }
        });
        console.log('[DEBUG] Verification email sent successfully');
    } catch (error) {
        console.error('[DEBUG] Verification email error:', error);
        const detail = typeof error === 'string' ? ` ${error}` : (error?.message ? ` ${error.message}` : '');
        lastAuthError = `Verification email failed to send.${detail}`;
        return false;
    }

    lastAuthError = `Verification code sent to ${user.email}.`;
    return true;
}

async function getDb() {
    if (!db) {
        try {
            db = await Database.load('sqlite:client_records.db');
            await ensureSchema(db);
            await db.execute(`
                CREATE TABLE IF NOT EXISTS app_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL
                )
            `);
            lastAuthError = '';
        } catch (error) {
            console.error("Database load/init failed:", error);
            const rawMessage = error?.message || String(error);
            lastAuthError = `Database unavailable. Raw error: ${rawMessage}. Check console for details.`;
            db = null; // Ensure db is null on failure
            throw new Error(lastAuthError);
        }
    }
    return db;
}

export async function checkFirstLogin() {
    try {
        const database = await getDb();
        const result = await database.select('SELECT COUNT(*) as count FROM users');
        lastAuthError = '';
        return Number(result?.[0]?.count ?? 0) === 0;
    } catch (error) {
        try {
            await new Promise((resolve) => setTimeout(resolve, 300));
            db = null;
            const database = await getDb();
            const result = await database.select('SELECT COUNT(*) as count FROM users');
            lastAuthError = '';
            return Number(result?.[0]?.count ?? 0) === 0;
        } catch (retryError) {
            console.error("Failed to check first login:", retryError);
            if (!lastAuthError) {
                const rawMessage = retryError?.message || String(retryError);
                lastAuthError = `Database unavailable: ${rawMessage}`;
            }
            return false;
        }
    }
}

export async function createUser(username, password, email = '', recoveryConfig = null) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedEmail = (email || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        if ((password || '').length < 8) {
            lastAuthError = 'Password must be at least 8 characters.';
            return false;
        }

        if (!normalizedEmail) {
            lastAuthError = 'Email is required for account recovery.';
            return false;
        }

        const existingUser = await database.select('SELECT id FROM users WHERE username = $1', [normalizedUsername]);
        if (existingUser?.length) {
            lastAuthError = 'User already exists. Please log in.';
            return false;
        }

        const passwordHash = CryptoJS.SHA256(password).toString();
        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();
        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }
        const recoveryEnabled = smtpHost && smtpPort > 0 && smtpUsername && smtpFrom && smtpPassword ? 1 : 0;
        if (!recoveryEnabled) {
            lastAuthError = 'SMTP settings are required for email verification.';
            return false;
        }

        await database.execute(
            'INSERT INTO users (username, password_hash, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified, email_verified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, NULL)',
            [normalizedUsername, passwordHash, normalizedEmail, smtpHost, smtpPort || null, smtpSecurity, smtpUsername, smtpFrom, smtpPassword, recoveryEnabled]
        );
        
        const sent = await sendEmailVerificationCode(database, normalizedUsername);
        if (!sent) {
            await database.execute('DELETE FROM users WHERE username = $1', [normalizedUsername]);
            await database.execute('DELETE FROM email_verification_codes WHERE username = $1', [normalizedUsername]);
            await database.execute('DELETE FROM password_reset_codes WHERE username = $1', [normalizedUsername]);

            return false;
        }

        encryptionKey = null;
        currentUser = null;
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error("Failed to create user:", error);
        lastAuthError = 'Failed to create user. Please try again.';
        return false;
    }
}

export async function loginUser(username, password) {
    try {
        encryptionKey = null;
        encryptionMode = 'legacy';
        currentUser = null;
        pendingRecoveryCode = '';
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const result = await database.select('SELECT * FROM users WHERE username = $1', [normalizedUsername]);
        if (!result?.length || !(await verifyPassword(password || '', result[0].password_hash))) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        const user = result[0];
        if (Number(user.email_verified) !== 1) {
            lastAuthError = 'Email not verified. Enter your verification code to continue.';
            return false;
        }

        const envelope = await readKeyEnvelope(database);
        if (envelope) {
            await openV2Account(database, normalizedUsername, password, envelope);
            lastAuthError = '';
            return true;
        }

        const legacyKey = deriveEncryptionKey(normalizedUsername, password);
        try {
            await migrateLegacyAccount(database, normalizedUsername, password, legacyKey, user.password_hash);
        } catch (migrationError) {
            if (!String(migrationError?.message || '').includes('existing database could not be unlocked')) {
                throw migrationError;
            }
            // Older releases could reset the login password without changing the
            // database key. If Touch ID still has that old key, migrate safely now.
            const encryptedState = (await readStateRow(database, 'main_state'))
                ?? (await readStateRow(database, LEGACY_STATE_BACKUP_KEY));
            if (!encryptedState) throw migrationError;
            const biometricSecret = await readBiometricLoginSecret(normalizedUsername);
            if (!biometricSecret) throw migrationError;
            try {
                decryptLegacyState(encryptedState, biometricSecret);
            } catch (_biometricError) {
                throw migrationError;
            }
            await migrateLegacyAccount(database, normalizedUsername, password, biometricSecret, user.password_hash);
        }
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error("Failed to login:", error);
        encryptionKey = null;
        encryptionMode = 'legacy';
        currentUser = null;
        lastAuthError = error?.message || 'Login failed. Please restart the app.';
        return false;
    }
}

export async function loginUserWithBiometricSecret(username, storedEncryptionKey) {
    try {
        encryptionKey = null;
        encryptionMode = 'legacy';
        currentUser = null;
        pendingRecoveryCode = '';
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedSecret = (storedEncryptionKey || '').trim();
        if (!normalizedUsername || !normalizedSecret) {
            lastAuthError = 'Saved biometric login is incomplete. Please log in with your password.';
            return false;
        }

        const result = await database.select('SELECT username, email_verified FROM users WHERE username = $1', [normalizedUsername]);
        if (!result?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        if (Number(result[0].email_verified) !== 1) {
            lastAuthError = 'Email not verified. Enter your verification code to continue.';
            return false;
        }

        const envelope = await readKeyEnvelope(database);
        if (envelope) {
            const encryptedState = await readStateRow(database, 'main_state');
            let dataKey = '';
            try {
                dataKey = await invokeTauriCommand('read_device_data_key', { username: normalizedUsername });
                if (!matchesDataKeyBinding(dataKey, normalizedUsername, envelope)) {
                    throw new Error('The saved local recovery key does not match the account.');
                }
                if (encryptedState) {
                    const plaintext = await decryptV2State(encryptedState, dataKey, normalizedUsername);
                    JSON.parse(plaintext);
                }
            } catch (_deviceKeyUnavailableOrInvalid) {
                dataKey = normalizedSecret;
                if (!matchesDataKeyBinding(dataKey, normalizedUsername, envelope)) {
                    throw new Error('The saved Touch ID key does not match the account data key.');
                }
                if (encryptedState) {
                    const plaintext = await decryptV2State(encryptedState, dataKey, normalizedUsername);
                    JSON.parse(plaintext);
                }
            }
            if (!envelope.recoveryKeyAcknowledged) {
                const recoveryCode = await invokeTauriCommand('generate_recovery_key');
                const updatedEnvelope = {
                    ...envelope,
                    recoveryWrap: await wrapDataKeyWithRecoveryCode(recoveryCode, dataKey),
                    recoveryKeyAcknowledged: false
                };
                await upsertAppState(database, DATA_KEY_ENVELOPE_KEY, JSON.stringify(updatedEnvelope));
                pendingRecoveryCode = recoveryCode;
            }
            encryptionKey = dataKey;
            encryptionMode = 'v2';
            currentUser = normalizedUsername;
            await storeLocalDataKey(normalizedUsername, dataKey);
        } else {
            lastAuthError = 'This database needs a one-time password migration. Enter your password to preserve and migrate your client data, then save the portable recovery key.';
            return false;
        }
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to log in with biometric secret:', error);
        lastAuthError = error?.message || 'Biometric login failed. Please use your password.';
        return false;
    }
}

export async function changePassword(currentPassword, newPassword) {
    if (!db || !currentUser || !encryptionKey) return false;

    try {
        const normalizedCurrentPassword = (currentPassword || '').trim();
        const normalizedNewPassword = (newPassword || '').trim();
        if (!normalizedCurrentPassword || !normalizedNewPassword) {
            lastAuthError = 'Current and new password are required.';
            return false;
        }

        const userResult = await db.select(
            'SELECT password_hash FROM users WHERE username = $1',
            [currentUser]
        );

        if (!userResult?.length || !(await verifyPassword(normalizedCurrentPassword, userResult[0].password_hash))) {
            lastAuthError = 'Incorrect current password.';
            return false;
        }

        if (encryptionMode === 'legacy') {
            const legacyKey = encryptionKey;
            await migrateLegacyAccount(db, currentUser, normalizedNewPassword, legacyKey, userResult[0].password_hash);
        } else {
            const keyEnvelopeRecord = await readKeyEnvelopeRecord(db);
            const envelope = keyEnvelopeRecord?.envelope;
            const unwrappedKey = await getDataKeyFromPassword(normalizedCurrentPassword, envelope);
            if (unwrappedKey !== encryptionKey) {
                throw new Error('The unlocked database key did not match the account key. Password was not changed.');
            }
            const newPasswordHash = await hashPassword(normalizedNewPassword);
            const nextEnvelope = {
                ...envelope,
                passwordWrap: await wrapDataKeyWithPassword(normalizedNewPassword, encryptionKey)
            };
            if ((await getDataKeyFromPassword(normalizedNewPassword, nextEnvelope)) !== encryptionKey
                || !matchesDataKeyBinding(encryptionKey, currentUser, nextEnvelope)
                || !(await verifyPassword(normalizedNewPassword, newPasswordHash))) {
                throw new Error('New password verification failed. The previous password was retained.');
            }
            const encryptedState = await readStateRow(db, 'main_state');
            await commitEncryptedAccountMigration({
                username: currentUser,
                expectedPasswordHash: userResult[0].password_hash,
                newPasswordHash,
                expectedKeyEnvelope: keyEnvelopeRecord.raw,
                keyEnvelope: JSON.stringify(nextEnvelope),
                expectedStateKey: encryptedState !== null ? 'main_state' : null,
                expectedStateValue: encryptedState,
                requireMainStateAbsent: encryptedState === null,
                backupStateKey: null,
                backupStateValue: null,
                replacementMainState: null,
                resetCode: null
            });
        }

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to change password:', error);
        lastAuthError = error?.message || 'Failed to change password.';
        return false;
    }
}

export function getLastAuthError() {
    return lastAuthError;
}

export function getCurrentUser() {
    return currentUser;
}

export function clearActiveSession() {
    encryptionKey = null;
    encryptionMode = 'legacy';
    currentUser = null;
}

export async function getBiometricAvailability() {
    if (typeof window?.__TAURI__?.core?.invoke !== 'function') {
        return {
            supported: false,
            available: false,
            enrolled: false,
            message: 'Biometric launch login is only available in the desktop app.'
        };
    }

    try {
        const availability = await invokeTauriCommand('get_biometric_availability');
        return {
            supported: availability?.supported !== false,
            available: !!availability?.available,
            enrolled: availability?.enrolled !== false,
            message: typeof availability?.message === 'string' ? availability.message : ''
        };
    } catch (error) {
        console.error('Failed to check biometric availability:', error);
        const message = error?.message || String(error) || 'Touch ID availability could not be checked.';
        lastAuthError = message;
        return {
            supported: true,
            available: false,
            enrolled: false,
            message
        };
    }
}

export async function storeCurrentBiometricLogin() {
    if (!currentUser || !encryptionKey) {
        lastAuthError = 'Unlock the app before enabling Touch ID login.';
        return false;
    }

    try {
        await invokeTauriCommand('store_biometric_secret', {
            username: currentUser,
            secret: encryptionKey
        });
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to store biometric login secret:', error);
        lastAuthError = error?.message || String(error) || 'Failed to enable Touch ID login.';
        return false;
    }
}

export async function readBiometricLoginSecret(username) {
    try {
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required for Touch ID login.';
            return null;
        }

        const secret = await invokeTauriCommand('read_biometric_secret', {
            username: normalizedUsername
        });
        lastAuthError = '';
        return typeof secret === 'string' ? secret : null;
    } catch (error) {
        console.error('Failed to read biometric login secret:', error);
        lastAuthError = error?.message || String(error) || 'Touch ID login failed.';
        return null;
    }
}

export async function removeBiometricLoginForUser(username) {
    try {
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            return true;
        }

        await invokeTauriCommand('remove_biometric_secret', {
            username: normalizedUsername
        });
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to remove biometric login secret:', error);
        lastAuthError = error?.message || String(error) || 'Failed to disable Touch ID login.';
        return false;
    }
}

export function consumePendingRecoveryCode() {
    const recoveryCode = pendingRecoveryCode;
    pendingRecoveryCode = '';
    return recoveryCode;
}

export async function acknowledgeRecoveryKey() {
    if (!db || !currentUser || encryptionMode !== 'v2') return false;
    try {
        const envelope = await readKeyEnvelope(db);
        if (!envelope) return false;
        await upsertAppState(db, DATA_KEY_ENVELOPE_KEY, JSON.stringify({
            ...envelope,
            recoveryKeyAcknowledged: true
        }));
        lastAuthError = '';
        return true;
    } catch (error) {
        lastAuthError = error?.message || 'Could not save recovery-key confirmation.';
        return false;
    }
}

export async function requestPasswordReset(username) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        const rows = await database.select(
            'SELECT username, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified FROM users WHERE username = $1',
            [normalizedUsername]
        );
        if (!rows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        const user = rows[0];
        if (Number(user.email_verified) !== 1) {
            lastAuthError = 'Email must be verified before password recovery can be used.';
            return false;
        }

        if (!user.recovery_enabled || !user.email || !user.smtp_host || !user.smtp_port || !user.smtp_username || !user.smtp_from || !user.smtp_password) {
            lastAuthError = 'Recovery email is not configured for this account.';
            return false;
        }

        const rateAllowed = await enforceCodeRateLimit(database, 'password_reset_codes', normalizedUsername, 'reset');
        if (!rateAllowed) {
            return false;
        }

        const code = await invokeTauriCommand('generate_password_reset_code');
        const codeHash = CryptoJS.SHA256(`${normalizedUsername}:${code}`).toString();
        const now = Date.now();
        const expiresAt = now + (10 * 60 * 1000);

        await database.execute('DELETE FROM password_reset_codes WHERE username = $1 OR expires_at < $2 OR used = 1', [normalizedUsername, now - (24 * 60 * 60 * 1000)]);
        await database.execute(
            'INSERT INTO password_reset_codes (username, code_hash, expires_at, attempts, used, created_at) VALUES ($1, $2, $3, 0, 0, $4)',
            [normalizedUsername, codeHash, expiresAt, now]
        );

        await invokeTauriCommand('send_password_reset_email', {
            args: {
                username: normalizedUsername,
                toEmail: user.email,
                smtpHost: user.smtp_host,
                smtpPort: Number(user.smtp_port),
                smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
                smtpUsername: user.smtp_username,
                smtpPassword: user.smtp_password,
                fromEmail: user.smtp_from,
                code
            }
        });

        lastAuthError = `Reset code sent to ${user.email}.`;
        return true;
    } catch (error) {
        console.error('Failed to request password reset:', error);
        lastAuthError = 'Failed to send reset code. Check SMTP settings.';
        return false;
    }
}

export async function requestEmailVerification(username) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        const rows = await database.select(
            'SELECT id FROM users WHERE username = $1',
            [normalizedUsername]
        );
        if (!rows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        return sendEmailVerificationCode(database, normalizedUsername);
    } catch (error) {
        console.error('Failed to request email verification:', error);
        lastAuthError = `Failed to send verification code: ${error}`;
        return false;
    }
}

export async function updateRecoverySettings(username, password, email = '', recoveryConfig = null, sendVerificationCode = true) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        const normalizedEmail = (email || '').trim();

        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return false;
        }

        if (!normalizedEmail) {
            lastAuthError = 'Recovery email is required.';
            return false;
        }

        const matched = await database.select(
            'SELECT id, password_hash FROM users WHERE username = $1',
            [normalizedUsername]
        );

        if (!matched?.length || !(await verifyPassword(normalizedPassword, matched[0].password_hash))) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();

        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }

        if (!smtpHost || smtpPort <= 0 || !smtpUsername || !smtpFrom || !smtpPassword) {
            lastAuthError = 'Complete all SMTP settings to continue.';
            return false;
        }

        await database.execute(
            'UPDATE users SET email = $1, smtp_host = $2, smtp_port = $3, smtp_security = $4, smtp_username = $5, smtp_from = $6, smtp_password = $7, recovery_enabled = 1, email_verified = 0, email_verified_at = NULL WHERE username = $8',
            [normalizedEmail, smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword, normalizedUsername]
        );

        if (sendVerificationCode) {
            const sent = await sendEmailVerificationCode(database, normalizedUsername);
            if (sent) {
                lastAuthError = 'SMTP settings updated. Verification code sent to your email.';
                return true;
            } else {
                const warningMessage = lastAuthError || 'Verification email failed to send.';
                lastAuthError = `SMTP settings updated. ${warningMessage}`;
                return true;
            }
        } else {
            lastAuthError = 'SMTP settings updated.';
            return true;
        }
    } catch (error) {
        console.error('Failed to update recovery settings:', error);
        lastAuthError = `Failed to update SMTP settings: ${error}`;
        return false;
    }
}

export async function getRecoverySettings(username, password) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();

        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return null;
        }

        const rows = await database.select(
            'SELECT email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, password_hash FROM users WHERE username = $1',
            [normalizedUsername]
        );

        if (!rows?.length || !(await verifyPassword(normalizedPassword, rows[0].password_hash))) {
            lastAuthError = 'Incorrect username or password.';
            return null;
        }

        const row = rows[0];
        lastAuthError = '';
        return {
            email: row.email || '',
            smtpHost: row.smtp_host || 'smtp.gmail.com',
            smtpPort: Number(row.smtp_port || 587),
            smtpSecurity: (row.smtp_security || 'starttls').toLowerCase(),
            smtpUsername: row.smtp_username || '',
            smtpFrom: row.smtp_from || ''
        };
    } catch (error) {
        console.error('Failed to load recovery settings:', error);
        lastAuthError = 'Failed to load SMTP settings.';
        return null;
    }
}

export async function testSmtpSettings(username, password, email = '', recoveryConfig = null) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        const normalizedEmail = (email || '').trim();

        if (!normalizedUsername || !normalizedPassword || !normalizedEmail) {
            lastAuthError = 'Username, password, and recovery email are required.';
            return false;
        }

        const rows = await database.select(
            'SELECT id, password_hash FROM users WHERE username = $1',
            [normalizedUsername]
        );
        if (!rows?.length || !(await verifyPassword(normalizedPassword, rows[0].password_hash))) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();

        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }

        await invokeTauriCommand('send_smtp_test_email', {
            args: {
                toEmail: normalizedEmail,
                smtpHost,
                smtpPort,
                smtpSecurity,
                smtpUsername,
                smtpPassword,
                fromEmail: smtpFrom
            }
        });

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to send SMTP test email:', error);
        const detail = error?.message ? ` Details: ${error.message}` : '';
        lastAuthError = `SMTP test failed. Check host, port, security, username, and app password.${detail}`;
        return false;
    }
}

export async function confirmEmailVerification(username, code) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedCode = (code || '').trim();

        if (!normalizedUsername || !normalizedCode) {
            lastAuthError = 'Username and verification code are required.';
            return false;
        }

        const userRows = await database.select('SELECT email_verified FROM users WHERE username = $1', [normalizedUsername]);
        if (!userRows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        if (Number(userRows[0].email_verified) === 1) {
            lastAuthError = '';
            return true;
        }

        const rows = await database.select(
            'SELECT id, code_hash, attempts, expires_at, used FROM email_verification_codes WHERE username = $1 ORDER BY created_at DESC LIMIT 1',
            [normalizedUsername]
        );

        if (!rows?.length) {
            lastAuthError = 'No active verification code found. Request a new code.';
            return false;
        }

        const row = rows[0];
        const now = Date.now();
        if (row.used || Number(row.expires_at) < now) {
            lastAuthError = 'Verification code expired. Request a new code.';
            return false;
        }

        if (Number(row.attempts) >= 5) {
            lastAuthError = 'Too many failed attempts. Request a new code.';
            return false;
        }

        const expectedHash = CryptoJS.SHA256(`${normalizedUsername}:verify:${normalizedCode}`).toString();
        if (expectedHash !== row.code_hash) {
            const attempts = Number(row.attempts) + 1;
            const used = attempts >= 5 ? 1 : 0;
            await database.execute('UPDATE email_verification_codes SET attempts = $1, used = $2 WHERE id = $3', [attempts, used, row.id]);
            lastAuthError = used
                ? 'Too many failed attempts. Request a new code.'
                : `Invalid code. ${Math.max(0, 5 - attempts)} attempt(s) remaining.`;
            return false;
        }

        const verifiedAt = Date.now();
        await database.execute('UPDATE users SET email_verified = 1, email_verified_at = $1 WHERE username = $2', [verifiedAt, normalizedUsername]);
        await database.execute('UPDATE email_verification_codes SET used = 1 WHERE id = $1', [row.id]);
        await database.execute('DELETE FROM email_verification_codes WHERE username = $1 AND id != $2', [normalizedUsername, row.id]);

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to confirm email verification:', error);
        lastAuthError = 'Email verification failed. Please try again.';
        return false;
    }
}

export async function confirmPasswordReset(username, code, newPassword, recoveryCode = '') {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedCode = (code || '').trim();
        if (!normalizedUsername || !normalizedCode || !newPassword) {
            lastAuthError = 'Username, code, and new password are required.';
            return false;
        }

        if (newPassword.length < 8) {
            lastAuthError = 'New password must be at least 8 characters.';
            return false;
        }

        const rows = await database.select(
            'SELECT id, code_hash, attempts, expires_at, used FROM password_reset_codes WHERE username = $1 ORDER BY created_at DESC LIMIT 1',
            [normalizedUsername]
        );

        if (!rows?.length) {
            lastAuthError = 'No active reset request found. Request a new code.';
            return false;
        }

        const row = rows[0];
        const now = Date.now();
        if (row.used || Number(row.expires_at) < now) {
            lastAuthError = 'Reset code expired. Request a new code.';
            return false;
        }

        if (Number(row.attempts) >= 5) {
            lastAuthError = 'Too many failed attempts. Request a new code.';
            return false;
        }

        const expectedHash = CryptoJS.SHA256(`${normalizedUsername}:${normalizedCode}`).toString();
        if (expectedHash !== row.code_hash) {
            const attempts = Number(row.attempts) + 1;
            const used = attempts >= 5 ? 1 : 0;
            await database.execute('UPDATE password_reset_codes SET attempts = $1, used = $2 WHERE id = $3', [attempts, used, row.id]);
            lastAuthError = used
                ? 'Too many failed attempts. Request a new code.'
                : `Invalid code. ${Math.max(0, 5 - attempts)} attempt(s) remaining.`;
            return false;
        }

        const userRows = await database.select('SELECT password_hash FROM users WHERE username = $1', [normalizedUsername]);
        if (!userRows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }
        const resetCodeCommit = {
            id: Number(row.id),
            username: normalizedUsername,
            codeHash: row.code_hash,
            now
        };
        const keyEnvelopeRecord = await readKeyEnvelopeRecord(database);
        const envelope = keyEnvelopeRecord?.envelope ?? null;

        if (envelope) {
            const encryptedState = await readStateRow(database, 'main_state');
            let dataKey = '';
            let recoveredFromDevice = false;
            try {
                dataKey = await invokeTauriCommand('read_device_data_key', { username: normalizedUsername });
                if (!matchesDataKeyBinding(dataKey, normalizedUsername, envelope)) {
                    throw new Error('The saved local recovery key does not match the account.');
                }
                recoveredFromDevice = true;
            } catch (_deviceKeyUnavailable) {
                try {
                    dataKey = await getDataKeyFromRecoveryCode(recoveryCode, envelope);
                    if (!matchesDataKeyBinding(dataKey, normalizedUsername, envelope)) {
                        throw new Error('The recovery key does not match this account.');
                    }
                } catch (_invalidRecoveryCode) {
                    lastAuthError = 'The account password was not changed. This Mac could not recover the database key. Enter the portable recovery key to preserve the existing client data.';
                    return false;
                }
            }

            try {
                if (encryptedState) {
                    const plaintext = await decryptV2State(encryptedState, dataKey, normalizedUsername);
                    JSON.parse(plaintext);
                }
            } catch (_invalidDataKey) {
                if (recoveredFromDevice && recoveryCode) {
                    try {
                        dataKey = await getDataKeyFromRecoveryCode(recoveryCode, envelope);
                        if (!matchesDataKeyBinding(dataKey, normalizedUsername, envelope)) {
                            throw new Error('The recovery key does not match this account.');
                        }
                        if (encryptedState) JSON.parse(await decryptV2State(encryptedState, dataKey, normalizedUsername));
                        recoveredFromDevice = false;
                    } catch (_invalidRecoveryKey) {
                        lastAuthError = 'The account password was not changed. The recovered key could not unlock the database.';
                        return false;
                    }
                } else {
                    lastAuthError = 'The account password was not changed. The recovered key could not unlock the database.';
                    return false;
                }
            }

            const nextEnvelope = {
                ...envelope,
                passwordWrap: await wrapDataKeyWithPassword(newPassword, dataKey),
                recoveryKeyAcknowledged: false
            };
            const modernPasswordHash = await hashPassword(newPassword);
            if ((await getDataKeyFromPassword(newPassword, nextEnvelope)) !== dataKey
                || !matchesDataKeyBinding(dataKey, normalizedUsername, nextEnvelope)
                || !(await verifyPassword(newPassword, modernPasswordHash))) {
                throw new Error('Password reset verification failed. No database changes were saved.');
            }
            await commitEncryptedAccountMigration({
                username: normalizedUsername,
                expectedPasswordHash: userRows[0].password_hash,
                newPasswordHash: modernPasswordHash,
                expectedKeyEnvelope: keyEnvelopeRecord.raw,
                keyEnvelope: JSON.stringify(nextEnvelope),
                expectedStateKey: encryptedState !== null ? 'main_state' : null,
                expectedStateValue: encryptedState,
                requireMainStateAbsent: encryptedState === null,
                backupStateKey: null,
                backupStateValue: null,
                replacementMainState: null,
                resetCode: resetCodeCommit
            });
            await storeLocalDataKey(normalizedUsername, dataKey);
        } else {
            const legacyEncryptedState = (await readStateRow(database, 'main_state'))
                ?? (await readStateRow(database, LEGACY_STATE_BACKUP_KEY));
            if (legacyEncryptedState) {
                let legacyKey = '';
                try {
                    legacyKey = await invokeTauriCommand('read_device_data_key', { username: normalizedUsername });
                    decryptLegacyState(legacyEncryptedState, legacyKey);
                } catch (_notLegacyDeviceKey) {
                    legacyKey = await readBiometricLoginSecret(normalizedUsername) || '';
                }
                try {
                    if (!legacyKey) throw new Error('No local key is available.');
                    decryptLegacyState(legacyEncryptedState, legacyKey);
                } catch (_unavailableLegacyKey) {
                    lastAuthError = 'The account password was not changed. Email verification alone cannot unlock this older encrypted database. Use the old password, Touch ID if it still has the old database key, or restore an encrypted backup.';
                    return false;
                }
                await migrateLegacyAccount(
                    database,
                    normalizedUsername,
                    newPassword,
                    legacyKey,
                    userRows[0].password_hash,
                    resetCodeCommit
                );
            } else {
                await initializeV2Account(database, normalizedUsername, newPassword, userRows[0].password_hash, resetCodeCommit);
            }
        }

        clearActiveSession();

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to confirm password reset:', error);
        lastAuthError = error?.message || 'Password reset failed. Please try again.';
        return false;
    }
}

export async function deleteUserAccount(username, password) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return false;
        }

        const matched = await database.select(
            'SELECT id, password_hash FROM users WHERE username = $1',
            [normalizedUsername]
        );

        if (!matched?.length || !(await verifyPassword(normalizedPassword, matched[0].password_hash))) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        await database.execute('DELETE FROM password_reset_codes WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM email_verification_codes WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM users WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM app_state');
        await removeBiometricLoginForUser(normalizedUsername);
        try {
            await invokeTauriCommand('remove_device_data_key', { username: normalizedUsername });
        } catch (_keychainError) {
        }

        if (currentUser === normalizedUsername) {
            encryptionKey = null;
            encryptionMode = 'legacy';
            currentUser = null;
        }

        db = null;
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to delete account:', error);
        lastAuthError = 'Failed to delete account.';
        return false;
    }
}

const sqlEscape = (value) => {
    if (value === null || value === undefined) return 'NULL';
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NULL';
    if (typeof value === 'boolean') return value ? '1' : '0';
    return `'${String(value).replace(/'/g, "''")}'`;
};

export async function exportEncryptedSqlDump() {
    if (!db || !encryptionKey) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    const schemaRows = await db.select(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    );

    let sqlDump = '-- SmartEMR SQL Export\n';
    sqlDump += `-- Generated: ${new Date().toISOString()}\n\n`;

    for (const row of schemaRows) {
        sqlDump += `${row.sql};\n`;

        const rows = await db.select(`SELECT * FROM ${row.name}`);
        if (rows.length > 0) {
            const columns = Object.keys(rows[0]);
            for (const record of rows) {
                const values = columns.map((column) => sqlEscape(record[column])).join(', ');
                sqlDump += `INSERT INTO ${row.name} (${columns.join(', ')}) VALUES (${values});\n`;
            }
        }

        sqlDump += '\n';
    }

    const encryptedSqlDump = CryptoJS.AES.encrypt(sqlDump, encryptionKey).toString();
    return {
        format: 'client-records-sql-export',
        encrypted: true,
        algorithm: 'AES',
        createdAt: new Date().toISOString(),
        data: encryptedSqlDump
    };
}

const splitSqlStatements = (sqlScript) => {
    const statements = [];
    let current = '';
    let inSingleQuote = false;
    const stripLeadingComments = (statement) => {
        let value = statement.trim();
        while (value.startsWith('--')) {
            const lineEnd = value.indexOf('\n');
            if (lineEnd === -1) return '';
            value = value.slice(lineEnd + 1).trimStart();
        }
        return value;
    };

    for (let index = 0; index < sqlScript.length; index += 1) {
        const char = sqlScript[index];
        const nextChar = sqlScript[index + 1];

        if (char === "'" && inSingleQuote && nextChar === "'") {
            current += "''";
            index += 1;
            continue;
        }

        if (char === "'") {
            inSingleQuote = !inSingleQuote;
            current += char;
            continue;
        }

        if (!inSingleQuote && char === ';') {
            const trimmed = stripLeadingComments(current);
            if (trimmed) {
                statements.push(trimmed);
            }
            current = '';
            continue;
        }

        current += char;
    }

    const trailing = stripLeadingComments(current);
    if (trailing) {
        statements.push(trailing);
    }

    return statements;
};

async function replaceDatabaseFromSqlDump(sqlDumpText, legacyBackupKey = '') {
    if (!db) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    if (typeof sqlDumpText !== 'string' || sqlDumpText.trim().length === 0) {
        throw new Error('SQL import file is empty or invalid.');
    }

    const statements = splitSqlStatements(sqlDumpText);
    if (statements.length === 0) {
        throw new Error('No SQL statements found in import file.');
    }

    if (encryptionMode !== 'v2') {
        throw new Error('Sign in with your password before importing a database so SmartEMR can secure the restored state.');
    }

    if (!sqlDumpText.trimStart().startsWith('-- SmartEMR SQL Export')) {
        throw new Error('This SQL file is not a recognized SmartEMR export. The database was not changed.');
    }

    const inspection = await invokeTauriCommand('inspect_encrypted_database_export', {
        statements,
        username: currentUser
    });
    if (!inspection?.accountFound) {
        throw new Error('The export does not contain the currently signed-in account. The database was not changed.');
    }
    const liveUserRows = await db.select('SELECT password_hash FROM users WHERE username = $1', [currentUser]);
    if (!liveUserRows?.length) {
        throw new Error('The current account could not be secured before import. The database was not changed.');
    }
    const liveKeyEnvelope = await readStateRow(db, DATA_KEY_ENVELOPE_KEY);
    if (!liveKeyEnvelope || !(await readKeyEnvelope(db))) {
        throw new Error('The current database key could not be secured before import. The database was not changed.');
    }
    const importedStateValue = typeof inspection.mainState === 'string' ? inspection.mainState : null;
    let replacementMainState = null;
    let legacyBackupStateKey = null;
    if (importedStateValue !== null) {
        let statePlaintext = '';
        const importedLegacyState = !isV2EncryptedState(importedStateValue);
        if (importedLegacyState) {
            if (!legacyBackupKey) {
                throw new Error('This older export uses its previous encryption key. The database was not changed.');
            }
            statePlaintext = decryptLegacyState(importedStateValue, legacyBackupKey);
            legacyBackupStateKey = `${LEGACY_STATE_BACKUP_KEY}_import_${Date.now()}`;
        } else {
            statePlaintext = await decryptV2State(importedStateValue, encryptionKey, currentUser);
            JSON.parse(statePlaintext);
        }
        replacementMainState = await encryptV2State(statePlaintext, encryptionKey, currentUser);
        if ((await decryptV2State(replacementMainState, encryptionKey, currentUser)) !== statePlaintext) {
            throw new Error('The restored client data could not be verified. The database was not changed.');
        }
    }

    await invokeTauriCommand('restore_encrypted_database_export', {
        import: {
            username: currentUser,
            currentPasswordHash: liveUserRows[0].password_hash,
            keyEnvelope: liveKeyEnvelope,
            statements,
            expectedImportedState: importedStateValue,
            replacementMainState,
            legacyBackupStateKey
        }
    });
}

export async function importSqlDump(sqlDumpText) {
    return replaceDatabaseFromSqlDump(sqlDumpText);
}

export async function importEncryptedSqlDump(exportPayload) {
    if (!db || !encryptionKey) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    if (!exportPayload || typeof exportPayload !== 'object') {
        throw new Error('Invalid encrypted SQL import payload.');
    }

    if (exportPayload.format !== 'client-records-sql-export' || typeof exportPayload.data !== 'string') {
        throw new Error('Unsupported SQL import format.');
    }

    let decryptedSql = '';
    try {
        decryptedSql = CryptoJS.AES.decrypt(exportPayload.data, encryptionKey).toString(CryptoJS.enc.Utf8);
    } catch (_currentKeyError) {
    }
    let legacyBackupKey = '';
    if (!decryptedSql?.trimStart().startsWith('-- SmartEMR SQL Export') && encryptionMode === 'v2') {
        const envelope = await readKeyEnvelope(db);
        if (envelope?.legacyBackupKeyEnvelope) {
            legacyBackupKey = await decryptV2State(envelope.legacyBackupKeyEnvelope, encryptionKey, currentUser);
            try {
                decryptedSql = CryptoJS.AES.decrypt(exportPayload.data, legacyBackupKey).toString(CryptoJS.enc.Utf8);
            } catch (_legacyKeyError) {
                decryptedSql = '';
            }
        }
    }
    if (!decryptedSql?.trimStart().startsWith('-- SmartEMR SQL Export')) {
        throw new Error('Failed to decrypt this SQL export with the current or preserved legacy key. The database was not changed.');
    }

    await replaceDatabaseFromSqlDump(decryptedSql, legacyBackupKey);
}

export async function saveState(state) {
    if (!db || !encryptionKey) return false;
    
    try {
        const encryptedState = encryptionMode === 'v2'
            ? await encryptV2State(JSON.stringify(state), encryptionKey, currentUser)
            : encryptStateString(state, encryptionKey);
        await upsertAppState(db, 'main_state', encryptedState);
        return true;
    } catch (error) {
        console.error("Failed to save state to database:", error);
        return false;
    }
}

export async function loadState() {
    if (!db || !encryptionKey) return null;
    
    try {
        const result = await db.select('SELECT value FROM app_state WHERE key = $1', ['main_state']);
        
        if (result && result.length > 0) {
            const encryptedState = result[0].value;
            if (encryptionMode === 'v2') {
                const plaintext = await decryptV2State(encryptedState, encryptionKey, currentUser);
                return JSON.parse(plaintext);
            }
            const decryptedString = decryptLegacyState(encryptedState, encryptionKey);
            return JSON.parse(decryptedString);
        }
        return null;
    } catch (error) {
        console.error("Failed to load state from database:", error);
        throw error; // Re-throw to handle incorrect password
    }
}

export function isDatabaseInitialized() {
    return db !== null && encryptionKey !== null;
}
