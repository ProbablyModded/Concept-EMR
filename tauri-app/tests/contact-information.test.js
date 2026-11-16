import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const path of ['index.html', 'src/index.html']) {
    test(`${path} edits contact details in Client Information and preserves legacy contact records`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /id="clientInformationModal"/);
        assert.match(html, /id="clientPhoneNumberInput"/);
        assert.match(html, /id="clientEmailInput"/);
        assert.match(html, /const formatClientPhoneInput =/);
        assert.match(html, /replace\(\/\\D\/g, ''\)/);
        assert.match(html, /slice\(0, 10\)/);
        assert.match(html, /const CLIENT_EMAIL_PATTERN = \/\^\[\^\\s@\]\+@\[\^\\s@\]\+\\\.\[\^\\s@\]\+\$\//);
        assert.match(html, /clientInformationVersion: 1/);
        assert.match(html, /const syncLegacyPrimaryContactValue =/);
        assert.match(html, /if \(enteredPhone !== originalPhone\) syncLegacyPrimaryContactValue\(client, 'phones', phoneNumber\)/);
        assert.match(html, /if \(enteredEmail !== originalEmail\) syncLegacyPrimaryContactValue\(client, 'emails', client\.email\)/);
        assert.doesNotMatch(html, /id="contactTabBtn"/);
        assert.doesNotMatch(html, /id="contactContent"/);
        assert.doesNotMatch(html, /id="clientPhoneList"/);
        assert.doesNotMatch(html, /id="clientEmailList"/);
    });
    test(`${path} waits for encrypted persistence before closing Client Information`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
        const saveStart = html.indexOf('const saveClientInformation = async () => {');
        const saveEnd = html.indexOf('const openAddClientModal =', saveStart);
        const saveFunction = html.slice(saveStart, saveEnd);
        const databaseSavePosition = saveFunction.indexOf('saved = await saveDataToLocalStorage()');
        const closeModalPosition = saveFunction.indexOf("clientInformationModal.classList.add('hidden')");
        const autoSaveStart = html.indexOf('const shouldTriggerAutoSave = (el) =>');
        const autoSaveEnd = html.indexOf("document.addEventListener('input'", autoSaveStart);
        const autoSaveFunction = html.slice(autoSaveStart, autoSaveEnd);

        assert.ok(saveStart >= 0 && saveEnd > saveStart);
        assert.ok(databaseSavePosition >= 0 && closeModalPosition > databaseSavePosition);
        assert.match(saveFunction, /clearTimeout\(saveTimeout\)/);
        assert.match(saveFunction, /saveClientInformationBtn\.textContent = 'Saving\.\.\.'/);
        assert.match(saveFunction, /if \(!saved\) \{/);
        assert.match(autoSaveFunction, /el\.closest\?\.\('#clientInformationModal'\)/);
    });

}
