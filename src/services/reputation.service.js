const axios = require('axios');
const dns = require('dns').promises;
const logger = require('../utils/logger');

const TIMEOUT = parseInt(process.env.TIMEOUT_REPUTATION || 3000);

// Check IP reputation using AbuseIPDB (optional)
const checkAbuseIPDB = async (ip) => {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
        return { success: false, reason: 'No API key' };
    }

    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            timeout: TIMEOUT,
            headers: {
                'Key': apiKey,
                'Accept': 'application/json'
            },
            params: {
                ipAddress: ip,
                maxAgeInDays: 90
            }
        });

        const data = response.data.data;
        const abuseScore = data.abuseConfidenceScore;

        let score = 0;
        const flags = [];

        if (abuseScore > 75) {
            score = 40;
            flags.push('HIGH_ABUSE_SCORE');
        } else if (abuseScore > 50) {
            score = 25;
            flags.push('MEDIUM_ABUSE_SCORE');
        } else if (abuseScore > 25) {
            score = 10;
            flags.push('LOW_ABUSE_SCORE');
        }

        return {
            success: true,
            score,
            flags,
            details: {
                abuseScore,
                totalReports: data.totalReports,
                isWhitelisted: data.isWhitelisted
            }
        };
    } catch (error) {
        logger.warn('AbuseIPDB check failed:', error.message);
        return { success: false, error: error.message };
    }
};

// Resolve hostname to IP
const resolveIP = async (hostname) => {
    try {
        const addresses = await dns.resolve4(hostname);
        return addresses[0];
    } catch (error) {
        logger.warn(`DNS resolution failed for ${hostname}:`, error.message);
        return null;
    }
};

// Main reputation check
const checkReputation = async (parsedUrl) => {
    const { hostname } = parsedUrl;

    try {
        // Resolve IP
        const ip = await resolveIP(hostname);

        if (!ip) {
            return {
                success: false,
                score: 5,
                flags: ['DNS_RESOLUTION_FAILED'],
                details: {
                    error: 'Could not resolve IP'
                }
            };
        }

        // Check if IP is in suspicious range
        const ipParts = ip.split('.');
        const firstOctet = parseInt(ipParts[0]);

        // Check for suspicious hosting (e.g., residential IP ranges)
        // This is a simple heuristic
        let score = 0;
        const flags = [];

        // Try AbuseIPDB check (optional)
        const abuseCheck = await checkAbuseIPDB(ip);
        if (abuseCheck.success) {
            score += abuseCheck.score;
            flags.push(...abuseCheck.flags);
        }

        return {
            success: true,
            score,
            flags,
            details: {
                ip,
                abuseCheck: abuseCheck.details || null
            }
        };
    } catch (error) {
        logger.warn(`Reputation check failed for ${hostname}:`, error.message);
        return {
            success: false,
            score: 0,
            flags: ['REPUTATION_CHECK_FAILED'],
            details: {
                error: error.message
            }
        };
    }
};

module.exports = {
    checkReputation
};