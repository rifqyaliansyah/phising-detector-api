// Final scoring and verdict mapping with intelligent weighting

const calculateVerdict = (totalScore) => {
    if (totalScore >= 70) {
        return {
            verdict: 'HIGH_RISK',
            level: 'danger',
            recommendation: 'DO NOT ENTER CREDENTIALS - Likely phishing attempt. Avoid this website.'
        };
    } else if (totalScore >= 40) {
        return {
            verdict: 'SUSPICIOUS',
            level: 'warning',
            recommendation: 'Exercise caution. Verify the website authenticity before entering any sensitive information.'
        };
    } else if (totalScore >= 20) {
        return {
            verdict: 'LOW_RISK',
            level: 'info',
            recommendation: 'Minor concerns detected. Proceed with normal caution.'
        };
    } else {
        return {
            verdict: 'SAFE',
            level: 'success',
            recommendation: 'No significant phishing indicators detected.'
        };
    }
};

const generateSummary = (flags) => {
    const criticalFlags = [
        'TYPOSQUATTING',
        'CHAR_SUBSTITUTION',
        'EXACT_SUBDOMAIN',
        'BRAND_WITH_KEYWORDS',
        'EXTERNAL_FORM_ACTION',
        'HIGH_ABUSE_SCORE',
        'CERT_EXPIRED',
        'AT_SYMBOL',
        'HIDDEN_FORM',
        'CROSS_DOMAIN_REDIRECT',
        'BRAND_MISMATCH'
    ];

    const warningFlags = [
        'NO_HTTPS',
        'VERY_NEW_DOMAIN',
        'PHISHING_LANGUAGE',
        'SUSPICIOUS_LANGUAGE',
        'SELF_SIGNED_CERT',
        'EXCESSIVE_IFRAMES'
    ];

    const infoFlags = [
        'PASSWORD_FORM',
        'NEW_DOMAIN',
        'EXCESSIVE_EXTERNAL_LINKS'
    ];

    const hasCritical = flags.some(f => criticalFlags.includes(f));
    const hasWarning = flags.some(f => warningFlags.includes(f));
    const hasInfo = flags.some(f => infoFlags.includes(f));

    if (hasCritical) {
        return 'Critical phishing indicators detected. This website is highly suspicious.';
    } else if (hasWarning) {
        return 'Some phishing indicators detected. Exercise caution.';
    } else if (hasInfo) {
        return 'Minor concerns detected. Website appears mostly legitimate.';
    } else if (flags.length > 0) {
        return 'No significant concerns detected.';
    } else {
        return 'No security concerns detected.';
    }
};

const combineResults = (results) => {
    const {
        parsedUrl,
        heuristic,
        typosquatting,
        ssl,
        whois,
        content,
        reputation
    } = results;

    // Collect all flags
    const allFlags = [
        ...(parsedUrl.isHostedPlatform ? ['HOSTED_PLATFORM'] : []),
        ...(heuristic?.flags || []),
        ...(typosquatting?.isTyposquatting ? [typosquatting.matchType] : []),
        ...(ssl?.flags || []),
        ...(whois?.flags || []),
        ...(content?.flags || []),
        ...(reputation?.flags || [])
    ];

    // Calculate base scores
    let totalScore = 0;
    const heuristicScore = heuristic?.score || 0;
    const typosquattingScore = typosquatting?.score || 0;
    const sslScore = ssl?.score || 0;
    const whoisScore = whois?.score || 0;
    const contentScore = content?.score || 0;
    const reputationScore = reputation?.score || 0;

    totalScore += heuristicScore;
    totalScore += typosquattingScore;
    totalScore += sslScore;
    totalScore += reputationScore;

    // SMART SCORING: Adjust content and domain age scores based on context

    // 1. Domain age consideration
    const domainAgeInYears = whois?.details?.ageInYears || 0;
    const isOldDomain = domainAgeInYears >= 2; // 2+ years is established
    const isVeryOldDomain = domainAgeInYears >= 5; // 5+ years is very trusted

    if (isVeryOldDomain) {
        // Very old domains are very unlikely to be phishing
        // Reduce content score significantly if it's just password forms
        if (allFlags.includes('PASSWORD_FORM') && !allFlags.includes('EXTERNAL_FORM_ACTION')) {
            // This is likely a legitimate login page
            totalScore += Math.max(0, contentScore - 5); // Remove password form penalty
        } else {
            totalScore += contentScore;
        }

        // Don't add domain age score for very old domains
        totalScore += 0;
    } else if (isOldDomain) {
        // Established domain (2-5 years)
        // Reduce password form concern
        if (allFlags.includes('PASSWORD_FORM') && !allFlags.includes('EXTERNAL_FORM_ACTION')) {
            totalScore += Math.max(0, contentScore - 3);
        } else {
            totalScore += contentScore;
        }
        totalScore += Math.max(0, whoisScore - 5); // Reduce domain age penalty
    } else {
        // New domain - full scoring applies
        totalScore += whoisScore;
        totalScore += contentScore;

        // NEW DOMAIN + PASSWORD FORM = Extra suspicious
        if (allFlags.includes('PASSWORD_FORM') && (allFlags.includes('VERY_NEW_DOMAIN') || allFlags.includes('NEW_DOMAIN'))) {
            totalScore += 10;
            allFlags.push('NEW_DOMAIN_WITH_LOGIN');
        }
    }

    // 2. SSL + Domain Age trust bonus
    if (isOldDomain && !allFlags.includes('NO_HTTPS') && !allFlags.includes('SELF_SIGNED_CERT')) {
        // Established domain with proper SSL - likely legitimate
        totalScore = Math.max(0, totalScore - 5);
    }

    // 3. Critical combinations
    if (allFlags.includes('EXTERNAL_FORM_ACTION') && allFlags.includes('PASSWORD_FORM')) {
        // Password form posting to external domain = VERY suspicious
        totalScore += 20;
    }

    if (allFlags.includes('TYPOSQUATTING') && allFlags.includes('PASSWORD_FORM')) {
        // Typosquatting + login form = Definitely phishing
        totalScore += 15;
    }

    // 4. Hosted platform considerations
    if (parsedUrl.isHostedPlatform && typosquatting?.isTyposquatting) {
        totalScore += 10;
    }

    // Get verdict
    const verdictData = calculateVerdict(totalScore);
    const summary = generateSummary(allFlags);

    // Build detailed response
    return {
        url: parsedUrl.url,
        verdict: verdictData.verdict,
        riskScore: Math.min(totalScore, 100), // Cap at 100
        level: verdictData.level,
        summary,
        recommendation: verdictData.recommendation,
        flags: [...new Set(allFlags)], // Remove duplicates
        analysis: {
            domain: {
                hostname: parsedUrl.hostname,
                rootDomain: parsedUrl.rootDomain,
                subdomain: parsedUrl.subdomain,
                isHostedPlatform: parsedUrl.isHostedPlatform,
                platform: parsedUrl.platform
            },
            heuristic: heuristic?.details || null,
            typosquatting: typosquatting?.isTyposquatting ? {
                matchedBrand: typosquatting.matchedBrand,
                matchType: typosquatting.matchType,
                confidence: typosquatting.confidence
            } : null,
            ssl: ssl?.details || null,
            domainAge: whois?.details || null,
            content: content?.details || null,
            reputation: reputation?.details || null
        },
        scores: {
            heuristic: heuristicScore,
            typosquatting: typosquattingScore,
            ssl: sslScore,
            domainAge: whoisScore,
            content: contentScore,
            reputation: reputationScore,
            total: Math.min(totalScore, 100)
        }
    };
};

module.exports = {
    calculateVerdict,
    generateSummary,
    combineResults
};