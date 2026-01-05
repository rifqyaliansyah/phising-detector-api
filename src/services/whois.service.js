const { exec } = require('child_process');
const { promisify } = require('util');
const logger = require('../utils/logger');

const execPromise = promisify(exec);
const TIMEOUT = parseInt(process.env.TIMEOUT_WHOIS || 5000);

// Parse creation date from WHOIS output
const parseCreationDate = (whoisText) => {
    const patterns = [
        /Creation Date:\s*(.+)/i,
        /Created:\s*(.+)/i,
        /Registered on:\s*(.+)/i,
        /Registration Time:\s*(.+)/i,
        /created:\s*(.+)/i
    ];

    for (const pattern of patterns) {
        const match = whoisText.match(pattern);
        if (match && match[1]) {
            const dateStr = match[1].trim();
            try {
                const date = new Date(dateStr);
                if (!isNaN(date.getTime())) {
                    return date;
                }
            } catch (e) {
                // Continue to next pattern
            }
        }
    }

    return null;
};

const checkDomainAge = async (rootDomain) => {
    try {
        // Try to execute whois command
        const { stdout, stderr } = await execPromise(`whois ${rootDomain}`, {
            timeout: TIMEOUT
        });

        if (stderr) {
            logger.warn(`WHOIS stderr for ${rootDomain}:`, stderr);
        }

        const creationDate = parseCreationDate(stdout);

        if (!creationDate) {
            return {
                success: false,
                score: 0,
                flags: [],
                details: {
                    error: 'Could not parse creation date'
                }
            };
        }

        const now = new Date();
        const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
        const ageInYears = ageInDays / 365;

        let score = 0;
        const flags = [];

        if (ageInDays < 30) {
            score = 30;
            flags.push('VERY_NEW_DOMAIN');
        } else if (ageInDays < 90) {
            score = 20;
            flags.push('NEW_DOMAIN');
        } else if (ageInDays < 180) {
            score = 10;
            flags.push('RECENT_DOMAIN');
        }

        return {
            success: true,
            score,
            flags,
            details: {
                creationDate: creationDate.toISOString(),
                ageInDays,
                ageInYears: parseFloat(ageInYears.toFixed(2))
            }
        };
    } catch (error) {
        logger.warn(`WHOIS check failed for ${rootDomain}:`, error.message);

        // WHOIS failed - bisa karena rate limit, command not found, dll
        return {
            success: false,
            score: 0,
            flags: ['WHOIS_CHECK_FAILED'],
            details: {
                error: error.message
            }
        };
    }
};

module.exports = {
    checkDomainAge
};