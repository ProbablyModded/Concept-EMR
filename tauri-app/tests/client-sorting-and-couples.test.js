import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const path of ['index.html', 'src/index.html']) {
    test(`${path} offers persistent client sorting without rewriting client order`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /<span class="client-sort-label">Sort by<\/span>/);
        assert.match(html, /<option value="first">First<\/option>/);
        assert.match(html, /<option value="last">Last<\/option>/);
        assert.match(html, /<option value="appt">Appt<\/option>/);
        assert.match(html, /localStorage\.setItem\(CLIENT_SORT_PREFERENCE_KEY, clientSortMode\)/);
        assert.match(html, /const getSortedMainBankClients = \(clients\) => clients\.slice\(\)\.sort/);
        assert.match(html, /getSortedMainBankClients\(getMainBankClients\(\)\)/);
        assert.match(html, /return rightAppointment - leftAppointment/);
        assert.doesNotMatch(html, /sortClientsBtn/);
        assert.doesNotMatch(html, /reorderVisibleClientSlots\(sortedMainIds\)/);
    });

    test(`${path} accepts and uses every named partner in couples counseling`, async () => {
        const html = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');

        assert.match(html, /Add every partner in the couple or partnership/);
        assert.match(html, /\+ Add Partner/);
        assert.match(html, /sessionMembersDraft\.push\(createEmptySessionMember\(\)\)/);
        assert.match(html, /const normalizeSessionMembers = \(value\) => \{[\s\S]*?return source\.map\(/);
        assert.match(html, /const memberLines = members\.map\(\(member, index\) =>/);
        assert.match(html, /\*\*\$\{memberLabel\} \$\{index \+ 1\}:\*\* \$\{name\}/);
    });
}
