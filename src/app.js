require('dotenv').config();
const express = require('express');
const logger = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`);
    next();
});

// CORS (simple implementation)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }

    next();
});

// Routes
const checkRoute = require('./routes/check.route');
app.use('/api', checkRoute);

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'Phishing Detector API',
        version: '1.0.0',
        endpoints: {
            check: 'POST /api/check',
            health: 'GET /api/health'
        },
        documentation: 'See README.md for usage'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// Start server
app.listen(PORT, () => {
    logger.info(`Phishing Detector API running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`http://localhost:${PORT}`);
});

module.exports = app;