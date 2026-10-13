const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const request = require('supertest');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');

// Synthetic keys only. Production mode exercises Secure cookies and HTTPS checks.
Object.assign(process.env, {
    NODE_ENV: 'production', DB_URL: 'mongodb://127.0.0.1:27017/not_used',
    CLIENT_URL: 'https://app.example.test', API_URL: 'https://api.example.test',
    JWT_ACCESS_SECRET: randomBytes(32).toString('hex'),
    JWT_REFRESH_SECRET: randomBytes(32).toString('hex'),
});
const config = require('../config');
const { createApp } = require('../app');
const User = require('../models/user-model');
const Token = require('../models/token-model');
const tokenService = require('../service/token-service');
const mailService = require('../service/mail-service');
const password = 'a long test passphrase';
const origin = config.clientOrigin;
let mongo, app, passwordHash, deliveries;
const originalSendMail = mailService.sendActivationMail;

before(async () => {
    mongo = await MongoMemoryServer.create({ binary: { version: '8.2.6' } });
    await mongoose.connect(mongo.getUri(), { dbName: 'security_tests' });
    await Promise.all([User.init(), Token.init()]);
    passwordHash = await bcrypt.hash(password, config.bcryptCost);
});
beforeEach(async () => {
    await Promise.all([User.deleteMany({}), Token.deleteMany({})]);
    deliveries = [];
    mailService.sendActivationMail = async (to, link) => deliveries.push({ to, link });
    app = createApp();
});
after(async () => {
    mailService.sendActivationMail = originalSendMail;
    await mongoose.disconnect();
    if (mongo) await mongo.stop();
});

function post(path, body = {}) {
    return request(app).post('/api' + path).set('Origin', origin).send(body);
}
function cookie(response) {
    assert.ok(response.headers['set-cookie']);
    return response.headers['set-cookie'][0].split(';')[0];
}
function rawRefresh(response) { return decodeURIComponent(cookie(response).split('=')[1]); }
async function seed(email = 'alice@example.test', extra = {}) {
    return User.create({ email, password: passwordHash, isActivated: true, ...extra });
}
async function signIn(email = 'alice@example.test') {
    await seed(email);
    const response = await post('/login', { email, password });
    assert.equal(response.status, 200);
    return response;
}
async function me(accessToken, expectedStatus = 200) {
    return request(app).get('/api/me').set('Authorization', 'Bearer ' + accessToken).expect(expectedStatus);
}

test('registration stores cost-12 hash and activation digest, issues no session', async () => {
    const response = await post('/registration', { email: ' Alice@Example.test ', password }).expect(202);
    assert.equal(response.body.accessToken, undefined);
    assert.equal(response.body.refreshToken, undefined);
    assert.equal(response.headers['set-cookie'], undefined);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(await Token.countDocuments(), 0);
    const user = await User.findOne().select('+password +activationTokenHash +activationExpiresAt');
    assert.equal(user.email, 'alice@example.test');
    assert.equal(bcrypt.getRounds(user.password), 12);
    assert.equal(await bcrypt.compare(password, user.password), true);
    const token = deliveries[0].link.split('/').pop();
    assert.match(token, /^[a-f0-9]{64}$/);
    assert.equal(user.activationTokenHash, tokenService.hash(token));
    assert.notEqual(user.activationTokenHash, token);
    assert.ok(user.activationExpiresAt > new Date());
});

test('activation is one-use and allows login only after email confirmation', async () => {
    await post('/registration', { email: 'alice@example.test', password }).expect(202);
    await post('/login', { email: 'alice@example.test', password }).expect(401);
    const path = new URL(deliveries[0].link).pathname;
    await request(app).get(path).expect(303).expect('Location', origin);
    await request(app).get(path).expect(400);
    await post('/login', { email: 'alice@example.test', password }).expect(200);
    const user = await User.findOne().select('+activationTokenHash +activationExpiresAt');
    assert.equal(user.activationTokenHash, undefined);
    assert.equal(user.activationExpiresAt, undefined);
});

test('parallel activation consumes a verification token only once', async () => {
    await post('/registration', { email: 'alice@example.test', password }).expect(202);
    const path = new URL(deliveries[0].link).pathname;
    const responses = await Promise.all([request(app).get(path), request(app).get(path)]);
    assert.deepEqual(responses.map(r => r.status).sort(), [303, 400]);
});

test('expired or malformed activation links cannot activate an account', async () => {
    await post('/registration', { email: 'alice@example.test', password }).expect(202);
    await User.updateOne({}, { $set: { activationExpiresAt: new Date(Date.now() - 1000) } });
    await request(app).get(new URL(deliveries[0].link).pathname).expect(400);
    await request(app).get('/api/activate/not-a-token').expect(400);
    assert.equal((await User.findOne()).isActivated, false);
});

test('duplicate registration returns the same generic response without issuing a session', async () => {
    const first = await post('/registration', { email: 'alice@example.test', password }).expect(202);
    const second = await post('/registration', { email: 'alice@example.test', password }).expect(202);
    assert.deepEqual(second.body, first.body);
    assert.equal(deliveries.length, 1);
    assert.equal(await User.countDocuments(), 1);
});

test('pending legacy accounts can request verification without revealing account existence', async () => {
    await seed('pending@example.test', { isActivated: false });
    const known = await post('/resend-activation', { email: 'pending@example.test' }).expect(202);
    const unknown = await post('/resend-activation', { email: 'unknown@example.test' }).expect(202);
    assert.deepEqual(known.body, unknown.body);
    assert.equal(deliveries.length, 1);
    await request(app).get(new URL(deliveries[0].link).pathname).expect(303);
    await post('/login', { email: 'pending@example.test', password }).expect(200);
});

test('verification resend has a per-account cooldown and never mails activated accounts', async () => {
    await post('/registration', { email: 'pending@example.test', password }).expect(202);
    await post('/resend-activation', { email: 'pending@example.test' }).expect(202);
    await seed('activated@example.test');
    await post('/resend-activation', { email: 'activated@example.test' }).expect(202);
    assert.equal(deliveries.length, 1);
    const oldLink = deliveries[0].link;
    await User.updateOne({ email: 'pending@example.test' }, {
        $set: { activationExpiresAt: new Date(Date.now() + config.activationTtl - 61000) },
    });
    await post('/resend-activation', { email: 'pending@example.test' }).expect(202);
    assert.equal(deliveries.length, 2);
    await request(app).get(new URL(oldLink).pathname).expect(400);
    await request(app).get(new URL(deliveries[1].link).pathname).expect(303);
});

test('login overwrites legacy plaintext refresh records instead of retaining their secret', async () => {
    const user = await seed();
    await Token.collection.insertOne({ user: user._id, refreshToken: 'legacy-synthetic-token' });
    await post('/login', { email: user.email, password }).expect(200);
    const session = await Token.collection.findOne({ user: user._id });
    assert.equal(session.refreshToken, undefined);
    assert.match(session.tokenHash, /^[a-f0-9]{64}$/);
});

test('failed SMTP delivery returns a generic error and allows registration to be retried', async () => {
    mailService.sendActivationMail = async () => { throw new Error('smtp-password-and-secret-url'); };
    const response = await post('/registration', { email: 'alice@example.test', password }).expect(503);
    assert.deepEqual(response.body, { message: 'Service temporarily unavailable' });
    assert.equal(await User.countDocuments(), 0);
});

test('three-character passwords and bcrypt-truncated UTF-8 passwords are rejected', async () => {
    for (const badPassword of ['abc', 'x'.repeat(73), '😀'.repeat(19)]) {
        const response = await post('/registration', { email: 'alice@example.test', password: badPassword }).expect(400);
        assert.deepEqual(response.body, { message: 'Invalid request' });
        assert.ok(!response.text.includes(badPassword));
    }
    assert.equal(await User.countDocuments(), 0);
});

test('operator objects, arrays, missing credentials, and non-string input are rejected before queries', async () => {
    const payloads = [
        { email: { $ne: null }, password },
        { email: ['alice@example.test'], password },
        { email: 'alice@example.test', password: { $gt: '' } },
        { email: 123, password }, {},
    ];
    for (const payload of payloads) {
        const response = await post('/login', payload).expect(400);
        assert.deepEqual(response.body, { message: 'Invalid request' });
    }
});

test('unknown, wrong-password, and unactivated accounts share one login error', async () => {
    await seed();
    await seed('pending@example.test', { isActivated: false });
    const responses = [];
    for (const [email, candidate] of [
        ['nobody@example.test', password], ['alice@example.test', 'wrong'], ['pending@example.test', password],
    ]) responses.push(await post('/login', { email, password: candidate }).expect(401));
    for (const response of responses) assert.deepEqual(response.body, { message: 'Invalid email or password' });
});

test('successful login upgrades an existing weak bcrypt hash', async () => {
    const weakHash = await bcrypt.hash(password, 4);
    await seed('alice@example.test', { password: weakHash });
    await post('/login', { email: 'alice@example.test', password }).expect(200);
    const user = await User.findOne().select('+password');
    assert.equal(bcrypt.getRounds(user.password), 12);
    assert.equal(await bcrypt.compare(password, user.password), true);
});

test('/users is removed and /me exposes only the authenticated account DTO', async () => {
    const login = await signIn();
    await seed('bob@example.test');
    await request(app).get('/api/users').set('Authorization', 'Bearer ' + login.body.accessToken).expect(404);
    const response = await me(login.body.accessToken);
    assert.deepEqual(Object.keys(response.body).sort(), ['email', 'id', 'isActivated']);
    assert.equal(response.body.email, 'alice@example.test');
    assert.ok(!response.text.includes('bob@example.test'));
    assert.equal((await User.findOne()).password, undefined);
});

test('refresh secret is cookie-only; production cookie and response headers are hardened', async () => {
    const login = await signIn();
    assert.deepEqual(Object.keys(login.body).sort(), ['accessToken', 'user']);
    const setCookie = login.headers['set-cookie'][0];
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/api']) assert.ok(setCookie.includes(flag));
    assert.ok(!setCookie.includes('Domain='));
    assert.equal(login.headers['cache-control'], 'no-store');
    assert.equal(login.headers['x-powered-by'], undefined);
    assert.equal(login.headers['x-content-type-options'], 'nosniff');
    const stored = await Token.findOne().select('+tokenHash').lean();
    assert.equal(stored.refreshToken, undefined);
    assert.equal(stored.tokenHash, tokenService.hash(rawRefresh(login)));
    assert.ok(!JSON.stringify(stored).includes(rawRefresh(login)));
});

test('same-second JWT issuance has unique identifiers and separate token purposes', () => {
    const now = Date.now;
    try {
        const fixed = now();
        Date.now = () => fixed;
        const id = new mongoose.Types.ObjectId().toString();
        const sid = randomUUID();
        const expiry = new Date(fixed + 100000);
        const first = tokenService.generateTokens(id, sid, expiry);
        const second = tokenService.generateTokens(id, sid, expiry);
        assert.notEqual(first.refreshToken, second.refreshToken);
        assert.notEqual(first.accessToken, second.accessToken);
        assert.equal(tokenService.validateAccessToken(first.refreshToken), null);
        assert.equal(tokenService.validateRefreshToken(first.accessToken), null);
    } finally { Date.now = now; }
});

test('wrong algorithms, issuer, audience, missing expiry, wrong purpose, and malformed subjects fail validation', () => {
    const payload = { type: 'access', sid: randomUUID() };
    const options = {
        algorithm: 'HS256', subject: new mongoose.Types.ObjectId().toString(),
        issuer: config.issuer, audience: config.accessAudience, expiresIn: 60, jwtid: randomUUID(),
    };
    const { expiresIn, ...withoutExpiry } = options;
    const invalid = [
        jwt.sign(payload, config.accessSecret, { ...options, algorithm: 'HS384' }),
        jwt.sign(payload, config.accessSecret, { ...options, issuer: 'untrusted' }),
        jwt.sign(payload, config.accessSecret, { ...options, audience: 'other-api' }),
        jwt.sign(payload, config.accessSecret, withoutExpiry),
        jwt.sign({ ...payload, type: 'refresh' }, config.accessSecret, options),
        jwt.sign(payload, config.accessSecret, { ...options, subject: 'not-an-object-id' }),
        jwt.sign(payload, config.accessSecret, { ...options, expiresIn: -1 }),
        jwt.sign(payload, 'different-signing-secret', options),
        'invalid',
    ];
    for (const token of invalid) assert.equal(tokenService.validateAccessToken(token), null);
});

test('authentication rejects missing, malformed, or incorrect authorization schemes promptly', async () => {
    await request(app).get('/api/me').expect(401);
    const login = await signIn();
    for (const header of ['Basic ' + login.body.accessToken, 'Bearer broken', 'Bearer ' + login.body.accessToken + ' extra']) {
        await request(app).get('/api/me').set('Authorization', header).expect(401);
    }
});

test('refresh rotates once without extending the absolute session expiry', async () => {
    const login = await signIn();
    const expiry = (await Token.findOne()).expiresAt.getTime();
    const refreshed = await post('/refresh').set('Cookie', cookie(login)).expect(200);
    assert.notEqual(rawRefresh(refreshed), rawRefresh(login));
    assert.equal(refreshed.body.refreshToken, undefined);
    assert.equal((await Token.findOne()).expiresAt.getTime(), expiry);
    await me(refreshed.body.accessToken);
});

test('replaying a consumed refresh token revokes the family and its access tokens', async () => {
    const login = await signIn();
    const refreshed = await post('/refresh').set('Cookie', cookie(login)).expect(200);
    await post('/refresh').set('Cookie', cookie(login)).expect(401);
    await post('/refresh').set('Cookie', cookie(refreshed)).expect(401);
    await me(refreshed.body.accessToken, 401);
    assert.equal(await Token.countDocuments(), 0);
});

test('parallel refresh has exactly one winner and revokes the family on detected replay', async () => {
    const login = await signIn();
    const responses = await Promise.all([
        post('/refresh').set('Cookie', cookie(login)),
        post('/refresh').set('Cookie', cookie(login)),
    ]);
    assert.deepEqual(responses.map(r => r.status).sort(), [200, 401]);
    assert.equal(await Token.countDocuments(), 0);
    await me(responses.find(r => r.status === 200).body.accessToken, 401);
});

test('a previous login family cannot revoke the current login family', async () => {
    const old = await signIn();
    const current = await post('/login', { email: 'alice@example.test', password }).expect(200);
    await me(old.body.accessToken, 401);
    await post('/refresh').set('Cookie', cookie(old)).expect(401);
    await post('/refresh').set('Cookie', cookie(current)).expect(200);
});

test('database expiry is enforced without waiting for the MongoDB TTL monitor', async () => {
    const login = await signIn();
    await Token.updateOne({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await post('/refresh').set('Cookie', cookie(login)).expect(401);
    await me(login.body.accessToken, 401);
});

test('logout clears the scoped cookie and immediately invalidates refresh and access tokens', async () => {
    const login = await signIn();
    const logout = await post('/logout').set('Cookie', cookie(login)).expect(204);
    assert.match(logout.headers['set-cookie'][0], /Path=\/api/);
    assert.match(logout.headers['set-cookie'][0], /SameSite=Strict/);
    assert.equal(await Token.countDocuments(), 0);
    await me(login.body.accessToken, 401);
    await post('/refresh').set('Cookie', cookie(login)).expect(401);
});

test('missing or malformed refresh credentials fail closed; logout remains idempotent', async () => {
    await post('/refresh').expect(401);
    await post('/refresh').set('Cookie', 'refreshToken=broken').expect(401);
    await post('/logout').expect(204);
});

test('missing, null, hostile, and sibling-subdomain origins cannot mutate sessions', async () => {
    const login = await signIn();
    for (const source of [null, 'null', 'https://evil.example.test', origin + '.evil.test']) {
        const attempt = request(app).post('/api/logout').set('Cookie', cookie(login));
        if (source !== null) attempt.set('Origin', source);
        await attempt.expect(403);
    }
    await me(login.body.accessToken);
    await post('/refresh').set('Cookie', cookie(login)).expect(200);
});

test('GET refresh is read-only and explicitly requires POST', async () => {
    const login = await signIn();
    const hash = (await Token.findOne().select('+tokenHash')).tokenHash;
    await request(app).get('/api/refresh').set('Cookie', cookie(login)).expect(405).expect('Allow', 'POST');
    assert.equal((await Token.findOne().select('+tokenHash')).tokenHash, hash);
});

test('login requests are throttled before an eleventh password attempt', async () => {
    // Cheap malformed requests still consume the same public login budget.
    for (let index = 0; index < 10; index++) await post('/login', {}).expect(400);
    const response = await post('/login', {}).expect(429);
    assert.ok(response.headers['retry-after']);
    assert.ok(response.headers.ratelimit);
});

test('registration is throttled before a sixth attempt', async () => {
    for (let index = 0; index < 5; index++) await post('/registration', {}).expect(400);
    await post('/registration', {}).expect(429);
});

test('malformed and oversized JSON bodies return bounded generic errors', async () => {
    const malformed = await request(app).post('/api/login').set('Origin', origin)
        .set('Content-Type', 'application/json').send('{"password":"secret"').expect(400);
    assert.deepEqual(malformed.body, { message: 'Invalid JSON' });
    const oversized = await post('/login', { email: 'alice@example.test', password: 'x'.repeat(11000) }).expect(413);
    assert.deepEqual(oversized.body, { message: 'Request too large' });
});

test('unexpected errors expose neither database details nor stack traces in responses or logs', async () => {
    const login = await signIn();
    const originalFind = User.findById;
    const originalLog = console.error;
    const log = [];
    try {
        User.findById = () => { throw new Error('mongodb://private-secret-url'); };
        console.error = (...values) => log.push(values.join(' '));
        const response = await me(login.body.accessToken, 500);
        assert.deepEqual(response.body, { message: 'Internal server error' });
        assert.ok(!log.join().includes('private-secret-url'));
    } finally {
        User.findById = originalFind;
        console.error = originalLog;
    }
});

test('session uniqueness and TTL cleanup are real MongoDB indexes', async () => {
    const indexes = await Token.collection.indexes();
    assert.ok(indexes.some(index => index.key.user === 1 && index.unique));
    assert.ok(indexes.some(index => index.key.expiresAt === 1 && index.expireAfterSeconds === 0));
    const user = await seed();
    const record = { user: user._id, sessionId: randomUUID(), tokenHash: 'a'.repeat(64), expiresAt: new Date(Date.now() + 60000) };
    await Token.create(record);
    await assert.rejects(Token.create({ ...record, sessionId: randomUUID() }), { code: 11000 });
});

test('configuration rejects weak/shared secrets, unsafe origins, invalid ports, and missing database URI', () => {
    for (const overrides of [
        { JWT_ACCESS_SECRET: 'short' }, { JWT_REFRESH_SECRET: config.accessSecret },
        { CLIENT_URL: 'http://app.example.test' }, { API_URL: 'https://api.example.test/path' },
        { CLIENT_URL: 'https://user:password@app.example.test' }, { PORT: '0' }, { DB_URL: '' },
    ]) assert.throws(() => config.loadConfig({ ...process.env, ...overrides }));
});

test('maintenance migration preserves accounts, revokes sessions, and enables fresh activation', async () => {
    const active = await seed();
    await User.collection.updateOne({ _id: active._id }, { $set: { email: ' Alice@Example.test ' } });
    const pending = await seed('pending@example.test', { isActivated: false });
    await User.collection.updateOne({ _id: pending._id }, { $set: { activationLink: 'synthetic-legacy-link' } });
    await Token.collection.insertOne({ user: active._id, refreshToken: 'synthetic-legacy-token' });
    await promisify(execFile)(process.execPath, [path.resolve(__dirname, '../scripts/migrate-sessions.js')], {
        env: { ...process.env, DB_URL: mongo.getUri('security_tests') }, maxBuffer: 4096,
    });
    assert.equal(await Token.countDocuments(), 0);
    assert.equal(await User.countDocuments(), 2);
    const migrated = await User.collection.findOne({ _id: active._id });
    assert.equal(migrated.password, passwordHash);
    assert.equal(migrated.isActivated, true);
    assert.equal(migrated.email, 'alice@example.test');
    assert.equal((await User.collection.findOne({ _id: pending._id })).activationLink, undefined);
    await post('/resend-activation', { email: pending.email }).expect(202);
    assert.equal(deliveries.length, 1);
});

test('migration aborts before modifying data if normalized legacy emails would collide', async () => {
    const user = await seed();
    await User.collection.insertOne({ email: 'ALICE@example.test', password: passwordHash, isActivated: true });
    await Token.collection.insertOne({ user: user._id, refreshToken: 'synthetic-legacy-token' });
    await assert.rejects(promisify(execFile)(process.execPath, [path.resolve(__dirname, '../scripts/migrate-sessions.js')], {
        env: { ...process.env, DB_URL: mongo.getUri('security_tests') }, maxBuffer: 4096,
    }));
    assert.equal(await Token.countDocuments(), 1);
    assert.equal(await User.countDocuments(), 2);
    assert.ok(await User.collection.findOne({ email: 'ALICE@example.test' }));
});

test('mail adapter sends the verification capability to SMTP with production TLS and restricted content access', async () => {
    const nodemailer = require('nodemailer');
    const originalCreateTransport = nodemailer.createTransport;
    const oldEnv = { SMTP_HOST: process.env.SMTP_HOST, SMTP_FROM: process.env.SMTP_FROM, SMTP_SECURE: process.env.SMTP_SECURE };
    let transportOptions, message;
    try {
        Object.assign(process.env, { SMTP_HOST: 'smtp.example.test', SMTP_FROM: 'auth@example.test', SMTP_SECURE: 'false' });
        nodemailer.createTransport = options => {
            transportOptions = options;
            return { sendMail: async mail => { message = mail; } };
        };
        await originalSendMail.call(mailService, 'alice@example.test', 'https://api.example.test/api/activate/synthetic');
        assert.equal(transportOptions.requireTLS, true);
        assert.equal(transportOptions.disableFileAccess, true);
        assert.equal(transportOptions.disableUrlAccess, true);
        assert.equal(message.to, 'alice@example.test');
        assert.match(message.text, /https:\/\/api.example.test\/api\/activate\/synthetic/);
        assert.equal(message.html, undefined);
    } finally {
        nodemailer.createTransport = originalCreateTransport;
        for (const [key, value] of Object.entries(oldEnv)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
    }
});
