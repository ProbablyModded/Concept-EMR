import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('biometric login cannot bypass portable-key setup for an older database', async () => {
    const source = await readFile(new URL('../src/database.js', import.meta.url), 'utf8');
    const biometricLogin = source.slice(
        source.indexOf('export async function loginUserWithBiometricSecret'),
        source.indexOf('export async function changePassword')
    );

    assert.match(biometricLogin, /if \(!envelope\.recoveryKeyAcknowledged\)/);
    assert.match(biometricLogin, /generate_recovery_key/);
    assert.match(biometricLogin, /wrapDataKeyWithRecoveryCode\(recoveryCode, dataKey\)/);
    assert.match(biometricLogin, /pendingRecoveryCode = recoveryCode/);
    assert.match(biometricLogin, /This database needs a one-time password migration/);
    assert.match(biometricLogin, /return false;/);
});
