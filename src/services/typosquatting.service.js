const natural = require('natural');
const { BRANDS, TYPO_CHARS } = require('../config/brands');

// Levenshtein distance untuk similarity
const levenshteinDistance = (str1, str2) => {
    return natural.LevenshteinDistance(str1, str2);
};

// Normalize string untuk comparison
const normalize = (str) => {
    return str.toLowerCase()
        .replace(/[^a-z0-9]/g, '') // Remove non-alphanumeric
        .replace(/\s+/g, '');
};

// Detect character substitution
const hasCharacterSubstitution = (hostname, brand) => {
    const hostnameNorm = normalize(hostname);
    const brandNorm = normalize(brand);

    // Check common substitutions
    for (const [fake, real] of Object.entries(TYPO_CHARS)) {
        if (fake.length > 1) {
            // Multi-char substitution (e.g., 'rn' -> 'm')
            if (hostnameNorm.includes(fake) && brandNorm.includes(real[0])) {
                return true;
            }
        } else {
            // Single char substitution
            for (const realChar of real) {
                const brandWithFake = brandNorm.replace(new RegExp(realChar, 'g'), fake);
                if (hostnameNorm === brandWithFake) {
                    return true;
                }
            }
        }
    }

    return false;
};

// Main typosquatting detection
const detectTyposquatting = (parsedUrl) => {
    const { hostname, subdomain, rootDomain } = parsedUrl;
    const fullDomain = hostname.toLowerCase();

    let bestMatch = null;
    let minDistance = Infinity;
    let matchType = null;

    for (const brand of BRANDS) {
        const brandNorm = normalize(brand);
        const hostnameNorm = normalize(hostname);
        const subdomainNorm = normalize(subdomain);

        // 1. Exact match in subdomain (e.g., tokopedia.vercel.app)
        if (subdomainNorm.includes(brandNorm)) {
            // Check if it's exact or typo
            if (subdomainNorm === brandNorm) {
                // Exact brand in subdomain - likely phishing on hosted platform
                return {
                    isTyposquatting: true,
                    matchedBrand: brand,
                    matchType: 'EXACT_SUBDOMAIN',
                    confidence: 'HIGH',
                    score: 50
                };
            }
        }

        // 2. Character substitution (e.g., tok0pedia)
        if (hasCharacterSubstitution(hostname, brand)) {
            return {
                isTyposquatting: true,
                matchedBrand: brand,
                matchType: 'CHAR_SUBSTITUTION',
                confidence: 'HIGH',
                score: 50
            };
        }

        // 3. Levenshtein distance (typo detection)
        const distance = levenshteinDistance(hostnameNorm, brandNorm);
        const threshold = Math.max(2, Math.floor(brandNorm.length * 0.2)); // 20% of brand length

        if (distance <= threshold && distance < minDistance) {
            minDistance = distance;
            bestMatch = brand;
            matchType = 'SIMILARITY';
        }

        // 4. Contains brand with additions (e.g., tokopedia-login, secure-bca)
        if (hostnameNorm.includes(brandNorm) && hostnameNorm !== brandNorm) {
            const additions = hostnameNorm.replace(brandNorm, '');
            // If additions contain suspicious keywords
            if (additions.match(/login|verify|secure|account|official|auth/)) {
                return {
                    isTyposquatting: true,
                    matchedBrand: brand,
                    matchType: 'BRAND_WITH_KEYWORDS',
                    confidence: 'HIGH',
                    score: 45
                };
            }
        }
    }

    // If found similar brand
    if (bestMatch && minDistance <= 2) {
        return {
            isTyposquatting: true,
            matchedBrand: bestMatch,
            matchType,
            confidence: minDistance === 1 ? 'HIGH' : 'MEDIUM',
            score: minDistance === 1 ? 45 : 35,
            distance: minDistance
        };
    }

    return {
        isTyposquatting: false,
        score: 0
    };
};

module.exports = {
    detectTyposquatting
};