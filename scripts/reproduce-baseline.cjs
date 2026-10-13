const path = require('node:path');
const { createRequire } = require('node:module');
const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { execFileSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const assert = require('node:assert/strict');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const express = require('express');
const cookieParser = require('cookie-parser');
const request = require('supertest');
const bcrypt = require('bcrypt');

const repo = path.resolve(__dirname, '..');
const baseline = 'aaa13945d4c7dfd03e4510fdc109b92720fc52ec';
const directory = mkdtempSync(path.join(tmpdir(), 'jwt-baseline-'));
const sourceFiles = execFileSync('git', ['ls-tree', '-r', '--name-only', baseline], { cwd: repo, encoding: 'utf8' })
    .trim().split('\n').filter(name => /^(controllers|dtos|exceptions|middlewares|models|router|service)\/.+\.js$/.test(name));
for (const name of sourceFiles) {
    let code = execFileSync('git', ['show', baseline + ':' + name], { cwd: repo, encoding: 'utf8' });
    // uuid v4 and crypto.randomUUID are equivalent here. No vulnerable vendored packages are installed.
    if (name === 'service/user-service.js') {
        code = code.replace("const uuid = require('uuid');", "const uuid = { v4: require('node:crypto').randomUUID };");
    }
    const file = path.join(directory, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, code);
}
writeFileSync(path.join(directory, 'package.json'), '{"type":"commonjs"}');
symlinkSync(path.join(repo, 'node_modules'), path.join(directory, 'node_modules'), 'dir');
const legacyRequire = createRequire(path.join(directory, 'package.json'));
Object.assign(process.env, {
    JWT_ACCESS_SECRET: randomBytes(32).toString('hex'),
    JWT_REFRESH_SECRET: randomBytes(32).toString('hex'),
    CLIENT_URL: 'http://localhost:5173', API_URL: 'http://localhost:3001',
});

(async () => {
    let mongo;
    try {
        mongo = await MongoMemoryServer.create({ binary: { version: '8.2.6' } });
        await mongoose.connect(mongo.getUri(), { dbName: 'baseline_reproduction' });
        const User = legacyRequire('./models/user-model');
        const Token = legacyRequire('./models/token-model');
        await Promise.all([User.init(), Token.init()]);
        legacyRequire('./service/mail-service').sendActivationMail = async () => {};
        const app = express();
        app.use(express.json());
        app.use(cookieParser());
        app.use('/api', legacyRequire('./router'));
        // Preserve legacy status/message behavior without printing raw errors.
        app.use((error, req, res, next) => res.status(error.status || 500).json({ message: error.message }));
        const registration = await request(app).post('/api/registration')
            .send({ email: 'synthetic@example.test', password: 'abc' });
        assert.equal(registration.status, 200);
        const user = await User.findOne();
        const dump = await request(app).get('/api/users')
            .set('Authorization', 'Bearer ' + registration.body.accessToken);
        const service = legacyRequire('./service/token-service');
        const originalNow = Date.now;
        let first, second;
        try {
            const fixed = originalNow();
            Date.now = () => fixed;
            first = service.generateTokens({ id: String(user._id), email: user.email });
            second = service.generateTokens({ id: String(user._id), email: user.email });
        } finally { Date.now = originalNow; }
        const errors = [];
        for (const body of [
            { email: 'missing@example.test', password: 'abc' },
            { email: user.email, password: 'wrong' },
        ]) {
            const response = await request(app).post('/api/login').send(body);
            errors.push({ status: response.status, message: response.body.message });
        }
        const setCookie = registration.headers['set-cookie'][0];
        const cookie = setCookie.split(';')[0];
        const refreshes = await Promise.all([
            request(app).get('/api/refresh').set('Cookie', cookie),
            request(app).get('/api/refresh').set('Cookie', cookie),
        ]);
        const cookieJar = execFileSync('git', ['show', baseline + ':cookies.txt'], { cwd: repo, encoding: 'utf8' });
        const result = {
            baselineCommit: baseline,
            environment: 'Local Express + temporary MongoDB; synthetic accounts only',
            dependencyNote: 'Current patched dependencies; legacy uuid v4 replaced with crypto.randomUUID; dependency scan is recorded separately',
            threeCharacterPasswordAccepted: registration.status === 200,
            effectiveBcryptCost: bcrypt.getRounds(user.password),
            unverifiedRegistrationIssuesAccessToken: typeof registration.body.accessToken === 'string',
            refreshTokenExposedInJson: typeof registration.body.refreshToken === 'string',
            authenticatedUsersEndpointStatus: dump.status,
            passwordHashExposedInUsersResponse: dump.body.some(record => typeof record.password === 'string'),
            activationTokenExposedInUsersResponse: dump.body.some(record => typeof record.activationLink === 'string'),
            sameSecondRefreshTokensAreIdentical: first.refreshToken === second.refreshToken,
            parallelRefreshStatuses: refreshes.map(response => response.status),
            refreshTokenStoredInPlaintext: typeof (await Token.findOne()).refreshToken === 'string',
            cookieFlags: { httpOnly: /HttpOnly/i.test(setCookie), secure: /; Secure/i.test(setCookie), sameSite: /SameSite=/i.test(setCookie) },
            credentialErrors: errors,
            committedCookieJarContainsJwt: /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(cookieJar),
        };
        assert.equal(result.passwordHashExposedInUsersResponse, true);
        assert.equal(result.sameSecondRefreshTokensAreIdentical, true);
        assert.deepEqual(result.parallelRefreshStatuses, [200, 200]);
        assert.equal(result.refreshTokenExposedInJson, true);
        console.log(JSON.stringify(result, null, 2));
    } finally {
        await mongoose.disconnect();
        if (mongo) await mongo.stop();
        rmSync(directory, { recursive: true, force: true });
    }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
