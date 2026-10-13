function loadConfig(env = process.env) {
    const nodeEnv = env.NODE_ENV || 'development';
    if (!['development', 'test', 'production'].includes(nodeEnv)) {
        throw new Error('NODE_ENV must be development, test, or production');
    }
    const production = nodeEnv === 'production';
    const accessSecret = env.JWT_ACCESS_SECRET;
    const refreshSecret = env.JWT_REFRESH_SECRET;
    if (![accessSecret, refreshSecret].every(value => typeof value === 'string' && Buffer.byteLength(value) >= 32)) {
        throw new Error('JWT secrets must each contain at least 32 bytes; generate independent random values');
    }
    if (accessSecret === refreshSecret) {
        throw new Error('Access and refresh secrets must be different');
    }
    function origin(name) {
        const url = new URL(env[name]);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
            url.pathname !== '/' || url.search || url.hash || (production && url.protocol !== 'https:')) {
            throw new Error(`${name} must be an origin without credentials, path, query, or fragment; production requires HTTPS`);
        }
        return url.origin;
    }
    const port = Number(env.PORT || 3001);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
    if (!env.DB_URL || !/^mongodb(?:\+srv)?:\/\//.test(env.DB_URL)) throw new Error('DB_URL must be a MongoDB URI');
    return {
        nodeEnv, production, port, accessSecret, refreshSecret,
        dbUrl: env.DB_URL,
        clientOrigin: origin('CLIENT_URL'),
        apiOrigin: origin('API_URL'),
        issuer: 'jwt-authentication',
        accessAudience: 'jwt-authentication-api',
        refreshAudience: 'jwt-authentication-refresh',
        bcryptCost: 12,
        accessTtl: 15 * 60,
        refreshTtl: 30 * 24 * 60 * 60,
        activationTtl: 24 * 60 * 60 * 1000,
    };
}

module.exports = { ...loadConfig(), loadConfig };
