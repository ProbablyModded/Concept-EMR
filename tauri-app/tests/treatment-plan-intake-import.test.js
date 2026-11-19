import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const path of ['index.html', 'src/index.html']) {
    test(`${path} imports the selected client's full intake note into the treatment-plan builder`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /for="presentingProblemShorthandInput">Presenting Problem Shorthand<\/label>[\s\S]*?id="importIntakeNoteBtn"[^>]*>Import Intake Note/);
        assert.match(html, /const formatIntakeSessionForCopy = \(intakeSession\) =>/);
        assert.match(html, /const importIntakeSessionIntoGoalBuilder = \(intakeSession\) => \{[\s\S]*?formatIntakeSessionForCopy\(intakeSession\)[\s\S]*?presentingProblemShorthandInput\.value = intakeText/);
        assert.match(html, /const client = findClient\(activeGoalGeneratorClientId\);[\s\S]*?const intakeSessions = \(Array\.isArray\(client\.intakeSessions\) \? client\.intakeSessions : \[\]\)/);
        assert.match(html, /if \(intakeSessions\.length === 1\) \{[\s\S]*?importIntakeSessionIntoGoalBuilder\(intakeSessions\[0\]\)[\s\S]*?return;/);
        assert.match(html, /id="intakeNotePickerModal"[^>]*aria-modal="true"/);
        assert.match(html, /Choose an intake date/);
        assert.match(html, /toLocaleDateString\(\)/);
        assert.match(html, /toLocaleTimeString\(\[\], \{ hour: 'numeric', minute: '2-digit' \}\)/);
        assert.match(html, /client\.id !== activeGoalGeneratorClientId/);
    });

    test(`${path} places treatment-plan Save after the generated plan review`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
        const reviewIndex = html.indexOf('<div id="generatedGoalsReview"');
        const saveIndex = html.indexOf('<button id="applyGeneratedGoalsBtn"');

        assert.notEqual(reviewIndex, -1);
        assert.notEqual(saveIndex, -1);
        assert.ok(saveIndex > reviewIndex, 'Save should follow the generated/editable treatment plan');
    });
}
