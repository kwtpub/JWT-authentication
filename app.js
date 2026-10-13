const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const createRouter = require('./router');
const errorMiddleware = require('./exceptions/error-middleware');
const config = require('./config');

function createApp() {
    const app = express();
    app.disable('x-powered-by');
    // Keep trust proxy disabled: never trust client-supplied forwarding headers.
    app.use(helmet());
    app.use(cors({ origin: config.clientOrigin, credentials: true }));
    app.use('/api', (req, res, next) => {
        res.set('Cache-Control', 'no-store');
        next();
    });
    app.use(cookieParser());
    app.use('/api', createRouter());
    app.use((req, res) => res.status(404).json({ message: 'Not found' }));
    app.use(errorMiddleware);
    return app;
}

module.exports = { createApp };
