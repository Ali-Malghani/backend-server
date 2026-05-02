const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const errorHandler = require('./middleware/errorHandler');
const checkRoutes = require('./routes/checkRoutes');
const healthRoutes = require('./routes/healthRoutes');
const logger = require('./utils/logger');

const app = express();

// 1. Security Middleware
app.use(helmet());

// 2. CORS — restrict to your Chrome Extension ID only
// After publishing, replace YOUR_EXTENSION_ID with the real ID from the Chrome Web Store
// It looks like: chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef
const allowedOrigins = [
    'chrome-extension://YOUR_EXTENSION_ID'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g. curl health checks) or matching extension
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`Blocked CORS request from origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Body Parser
app.use(express.json());

// 4. Request Logging Middleware
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.originalUrl}`);
    next();
});

// 5. Routes
app.use('/check-url', checkRoutes);
app.use('/health', healthRoutes);

// 6. 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// 7. Global Error Handler
app.use(errorHandler);

module.exports = app;
