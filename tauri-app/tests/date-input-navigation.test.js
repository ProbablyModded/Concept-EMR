import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const path of ['index.html', 'src/index.html']) {
    test(`${path} uses compact single-field appointment and treatment-plan dates`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /id="appointmentDateTextInput"[^>]*inputmode="numeric"[^>]*placeholder="MM\/DD\/YYYY"/);
        assert.match(html, /formatCompactDateEntry\(digits\)/);
        assert.match(html, /const handleSingleDateTextInput =/);
        assert.match(html, /textInput\.addEventListener\('input', handleSingleDateTextInput\)/);
        assert.match(html, /parseCompactDateDigits\(digits\)/);
        assert.match(html, /data-date-picker-for="appointmentDateInput"/);
        assert.match(html, /data-single-date-input="appointmentDateInput"/);
        assert.match(html, /const initializeSingleDateInputs =/);
        assert.match(html, /initializeSingleDateInputs\(\);/);
        assert.match(html, /id="planItemStartDateInputText"[^>]*placeholder="MM\/DD\/YYYY"/);
        assert.match(html, /renderCompactDateControlMarkup\(`draftGoalStartDateInput\$\{goalIndex\}`/);
        assert.match(html, /renderCompactDateControlMarkup\(`draftObjectiveStartDateInput\$\{goalIndex\}_\$\{objIndex\}`/);
        assert.doesNotMatch(html, /segmented-date-control|data-date-segment=/);
    });
}
