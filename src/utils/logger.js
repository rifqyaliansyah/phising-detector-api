// Simple logger utility

const LOG_LEVELS = {
    ERROR: 'ERROR',
    WARN: 'WARN',
    INFO: 'INFO',
    DEBUG: 'DEBUG'
};

const log = (level, message, data = null) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level}] ${message}`;

    if (data) {
        console.log(logMessage, data);
    } else {
        console.log(logMessage);
    }
};

const error = (message, data = null) => {
    log(LOG_LEVELS.ERROR, message, data);
};

const warn = (message, data = null) => {
    log(LOG_LEVELS.WARN, message, data);
};

const info = (message, data = null) => {
    log(LOG_LEVELS.INFO, message, data);
};

const debug = (message, data = null) => {
    if (process.env.NODE_ENV === 'development') {
        log(LOG_LEVELS.DEBUG, message, data);
    }
};

module.exports = {
    error,
    warn,
    info,
    debug
};