const axios = require('axios');
const logger = require('../utils/logger');

const TIMEOUT = parseInt(process.env.TIMEOUT_WHOIS || 10000);
const ENABLE_WHOIS = process.env.ENABLE_WHOIS !== 'false';

const RDAP_BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap/domain';

const parseCreationDate = (rdapData) => {
    if (!rdapData.events || !Array.isArray(rdapData.events)) {
        return null;
    }

    const creationEvents = rdapData.events.filter(event =>
        event.eventAction === 'registration' ||
        event.eventAction === 'creation'
    );

    if (creationEvents.length > 0 && creationEvents[0].eventDate) {
        try {
            const date = new Date(creationEvents[0].eventDate);
            if (!isNaN(date.getTime())) {
                return date;
            }
        } catch (e) {
            logger.warn('Failed to parse RDAP creation date:', e.message);
        }
    }

    return null;
};

const checkDomainAge = async (rootDomain) => {
    if (!ENABLE_WHOIS) {
        logger.info(`Domain age check disabled for ${rootDomain}`);
        return {
            success: false,
            score: 0,
            flags: ['WHOIS_DISABLED'],
            details: {
                message: 'Domain age check is disabled'
            }
        };
    }

    try {
        const rdapUrl = `${RDAP_BOOTSTRAP_URL}/${rootDomain}`;

        logger.info(`Querying RDAP bootstrap: ${rdapUrl}`);

        const response = await axios.get(rdapUrl, {
            timeout: TIMEOUT,
            maxRedirects: 5,
            headers: {
                'Accept': 'application/json'
            }
        });

        const rdapData = response.data;

        if (!rdapData) {
            logger.warn(`No RDAP data for ${rootDomain}`);
            return {
                success: false,
                score: 0,
                flags: ['RDAP_NO_DATA'],
                details: {
                    error: 'No RDAP data available'
                }
            };
        }

        const creationDate = parseCreationDate(rdapData);

        if (!creationDate) {
            logger.warn(`Could not parse creation date for ${rootDomain}`);
            return {
                success: false,
                score: 0,
                flags: ['RDAP_PARSE_FAILED'],
                details: {
                    error: 'Could not parse creation date from RDAP'
                }
            };
        }

        const now = new Date();
        const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
        const ageInYears = ageInDays / 365;

        let score = 0;
        const flags = [];

        if (ageInDays < 0) {
            score = 0;
            flags.push('INVALID_CREATION_DATE');
        } else if (ageInDays < 30) {
            score = 30;
            flags.push('VERY_NEW_DOMAIN');
        } else if (ageInDays < 90) {
            score = 20;
            flags.push('NEW_DOMAIN');
        } else if (ageInDays < 180) {
            score = 10;
            flags.push('RECENT_DOMAIN');
        }

        logger.info(`RDAP success for ${rootDomain}: ${ageInDays} days old (created: ${creationDate.toISOString().split('T')[0]})`);

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
        logger.warn(`Domain age check failed for ${rootDomain}:`, error.message);

        return {
            success: false,
            score: 0,
            flags: ['DOMAIN_AGE_CHECK_FAILED'],
            details: {
                error: error.message
            }
        };
    }
};

module.exports = {
    checkDomainAge
};