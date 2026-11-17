import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const path of ['index.html', 'src/index.html']) {
    test(`${path} preloads all treatment-plan diagnoses with their substantiation`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /return substantiation \? `\$\{name\}\\n\$\{substantiation\}` : name/);
        assert.match(html, /\.join\('\\n\\n'\)/);
        assert.match(html, /goalDiagnosisInput\.value = formatDiagnosisWithSubstantiationText\(client\);/);
        assert.match(html, /presentingProblemShorthandInput\.value = ''/);
    });
}
