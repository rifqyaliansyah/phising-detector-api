const tls = require('tls');
const logger = require('../utils/logger');

const TIMEOUT = parseInt(process.env.TIMEOUT_SSL || 5000);

const checkSSL = (parsedUrl) => {
    return new Promise((resolve) => {
        const { hostname, protocol } = parsedUrl;

        // If not HTTPS, return immediately
        if (protocol !== 'https') {
            return resolve({
                hasHTTPS: false,
                score: 20,
                flags: ['NO_HTTPS'],
                details: {
                    protocol: 'http',
                    error: 'Not using HTTPS'
                }
            });
        }

        // Check SSL certificate
        const socket = tls.connect({
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false, // Don't reject self-signed certs
            timeout: TIMEOUT
        });

        socket.on('secureConnect', () => {
            try {
                const cert = socket.getPeerCertificate();
                socket.end();

                if (!cert || Object.keys(cert).length === 0) {
                    return resolve({
                        hasHTTPS: true,
                        isValid: false,
                        score: 15,
                        flags: ['INVALID_CERT'],
                        details: {
                            error: 'No certificate found'
                        }
                    });
                }

                const now = new Date();
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);

                const isExpired = now > validTo;
                const isNotYetValid = now < validFrom;
                const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

                const flags = [];
                let score = 0;

                if (isExpired) {
                    flags.push('CERT_EXPIRED');
                    score += 30;
                } else if (isNotYetValid) {
                    flags.push('CERT_NOT_YET_VALID');
                    score += 25;
                } else if (daysUntilExpiry < 30) {
                    flags.push('CERT_EXPIRING_SOON');
                    score += 10;
                }

                // Check issuer
                const issuer = cert.issuer?.O || '';
                const isSelfSigned = cert.issuer?.CN === cert.subject?.CN;

                if (isSelfSigned) {
                    flags.push('SELF_SIGNED_CERT');
                    score += 20;
                }

                resolve({
                    hasHTTPS: true,
                    isValid: !isExpired && !isNotYetValid,
                    score,
                    flags,
                    details: {
                        issuer,
                        validFrom: validFrom.toISOString(),
                        validTo: validTo.toISOString(),
                        daysUntilExpiry,
                        isSelfSigned,
                        subject: cert.subject?.CN || hostname
                    }
                });
            } catch (error) {
                socket.end();
                logger.warn('SSL check error:', error.message);
                resolve({
                    hasHTTPS: true,
                    isValid: false,
                    score: 10,
                    flags: ['SSL_CHECK_ERROR'],
                    details: {
                        error: error.message
                    }
                });
            }
        });

        socket.on('error', (error) => {
            socket.end();
            logger.warn(`SSL connection error for ${hostname}:`, error.message);
            resolve({
                hasHTTPS: true,
                isValid: false,
                score: 15,
                flags: ['SSL_CONNECTION_ERROR'],
                details: {
                    error: error.message
                }
            });
        });

        socket.on('timeout', () => {
            socket.end();
            resolve({
                hasHTTPS: true,
                isValid: null,
                score: 5,
                flags: ['SSL_TIMEOUT'],
                details: {
                    error: 'SSL check timeout'
                }
            });
        });
    });
};

module.exports = {
    checkSSL
};