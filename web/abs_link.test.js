// Booksync F2 + F3: dashboard tests for the Audiobookshelf link and the
// Hardcover OAuth connection.
// Run with: node --test web/app.test.js web/abs_link.test.js
const assert = require('node:assert/strict');
const test = require('node:test');

const elements = new Map();
global.window = {
    addEventListener() {},
    location: { pathname: '/' }
};
global.document = {
    addEventListener() {},
    getElementById(id) {
        return elements.get(id) || null;
    },
    createElement() {
        let text = '';
        return {
            set textContent(value) {
                text = String(value);
            },
            get innerHTML() {
                return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }
        };
    }
};

const { SyncProfileApp } = require('./static/app.js');

function createApp({ authEnabled = true, role = 'user' } = {}) {
    const app = Object.create(SyncProfileApp.prototype);
    app.authEnabled = authEnabled;
    app.currentUser = authEnabled ? { id: 'u', role } : null;
    app.absLinks = [];
    app.absUserOptions = [];
    return app;
}

test('only an approved link lets an owned profile sync when sign-in is on', () => {
    const app = createApp();
    const connected = { state: 'connected' };
    assert.equal(app.canSync({ state: 'approved' }, connected), true);
    for (const state of ['pending', 'none', 'rejected', 'bogus']) {
        assert.equal(app.canSync({ state }, connected), false, state);
    }
    assert.equal(app.canSync(undefined, connected), false);
});

// Booksync F3: Hardcover OAuth connection on the dashboard.

test('an approved link still needs a connected Hardcover to sync', () => {
    const app = createApp();
    const approved = { state: 'approved' };
    assert.equal(app.canSync(approved, { state: 'connected' }), true);
    assert.equal(app.canSync(approved, { state: 'needs_reconnect' }), false);
    assert.equal(app.canSync(approved, { state: 'none' }), false);
    assert.equal(app.canSync(approved, undefined), false);
});

test('the Hardcover button follows the connection state', () => {
    const app = createApp();
    assert.match(app.renderHardcoverButton({ state: 'none' }), /data-profile-action="hc-connect"[\s\S]*Connect Hardcover/);
    assert.match(app.renderHardcoverButton({ state: 'needs_reconnect' }), /data-profile-action="hc-connect"[\s\S]*Reconnect Hardcover/);
    assert.match(app.renderHardcoverButton({ state: 'connected' }), /data-profile-action="hc-disconnect"/);
    assert.match(app.renderHardcoverButton(undefined), /Connect Hardcover/);
});

test('the connected Hardcover account name is shown escaped', () => {
    const app = createApp();
    const html = app.renderHardcoverItem({ state: 'connected', username: '<script>x</script>' });
    assert.match(html, /Connected as &lt;script&gt;x&lt;\/script&gt;/);
    assert.doesNotMatch(html, /<script>/);
    assert.match(app.renderHardcoverItem({ state: 'needs_reconnect' }), /Reconnect to resume/);
});

test('only fixed result codes from the Hardcover redirect produce a message', () => {
    const app = createApp();
    assert.deepEqual(app.hardcoverResultMessage('connected'), ['Hardcover connected', 'success']);
    assert.equal(app.hardcoverResultMessage('error:issuer')[1], 'error');
    assert.equal(app.hardcoverResultMessage('<img src=x onerror=alert(1)>'), null);
    assert.equal(app.hardcoverResultMessage('error:anything-else'), null);
});

test('with sign-in off there is no link gate', () => {
    const app = createApp({ authEnabled: false });
    assert.equal(app.canSync(undefined), true);
});

test('the link button shows only when there is nothing pending or approved', () => {
    const app = createApp();
    assert.equal(app.canRelink({ state: 'none' }), true);
    assert.equal(app.canRelink({ state: 'rejected' }), true);
    assert.equal(app.canRelink({ state: 'pending' }), false);
    assert.equal(app.canRelink({ state: 'approved' }), false);
});

test('the member sees which Audiobookshelf user was matched, escaped', () => {
    const app = createApp();
    const html = app.renderABSLinkItem({ state: 'pending', abs_username: '<img src=x>' });
    assert.match(html, /waiting for approval/);
    assert.match(html, /&lt;img src=x&gt;/);
    assert.doesNotMatch(html, /<img/);
});

test('isAdmin follows the signed-in role', () => {
    assert.equal(createApp({ role: 'admin' }).isAdmin(), true);
    assert.equal(createApp({ role: 'user' }).isAdmin(), false);
    assert.equal(createApp({ authEnabled: false }).isAdmin(), false);
});

test('the admin table offers approve only for pending and escapes every field', () => {
    const container = { innerHTML: '' };
    elements.set('abs-links-list', container);
    const app = createApp({ role: 'admin' });
    app.absLinks = [
        { profile_id: 'p1', profile_name: 'One', owner_username: 'alice', abs_username: 'alice', abs_link_state: 'pending' },
        { profile_id: 'p2', profile_name: '<b>Two</b>', owner_username: 'bob', abs_username: 'bob', abs_link_state: 'approved' },
        { profile_id: 'p3', profile_name: 'Three', owner_username: '', abs_username: '', abs_link_state: 'none' }
    ];
    app.absUserOptions = [{ id: 'abs-1', username: 'carol', has_openid_link: false }];
    app.renderABSLinks();

    const rows = container.innerHTML.split('<tr data-profile-id=').slice(1);
    assert.equal(rows.length, 3);
    assert.match(rows[0], /data-link-action="approve"/);
    assert.match(rows[0], /data-link-action="reject"/);
    assert.doesNotMatch(rows[1], /data-link-action="approve"/);
    assert.match(rows[1], /data-link-action="reject"/);
    assert.doesNotMatch(rows[2], /data-link-action="(approve|reject)"/);
    assert.match(rows[2], /\(no owner\)/);
    assert.match(container.innerHTML, /&lt;b&gt;Two&lt;\/b&gt;/);
    assert.match(container.innerHTML, /carol \(no Pocket ID link\)/);
    elements.delete('abs-links-list');
});

// Booksync F4: Audiobookshelf settings are server-held, so neither profile
// form may offer or send them. Checked against the shipped sources.
test('neither profile form offers or sends Audiobookshelf settings', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const html = fs.readFileSync(path.join(__dirname, 'static', 'index.html'), 'utf8');
    const js = fs.readFileSync(path.join(__dirname, 'static', 'app.js'), 'utf8');
    for (const id of ['abs-url', 'abs-token', 'edit-abs-url', 'edit-abs-token']) {
        assert.equal(html.includes(`id="${id}"`), false, `form field ${id} is still in index.html`);
    }
    assert.equal(html.includes('name="audiobookshelf_url"'), false);
    assert.equal(html.includes('name="audiobookshelf_token"'), false);
    assert.equal(js.includes('audiobookshelf_token'), false, 'app.js still sends an ABS token');
    assert.equal(js.includes("audiobookshelf_url: formData"), false, 'app.js still sends an ABS URL');
    assert.equal(js.includes("'edit-abs-url'"), false);
});
