// Final scoring and verdict mapping

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
        'AT_SYMBOL'
    ];

    const warningFlags = [
        'NO_HTTPS',
        'VERY_NEW_DOMAIN',
        'PASSWORD_FORM',
        'SUSPICIOUS_KEYWORDS',
        'SELF_SIGNED_CERT',
        'SENSITIVE_CONTENT'
    ];

    const hasCritical = flags.some(f => criticalFlags.includes(f));
    const hasWarning = flags.some(f => warningFlags.includes(f));

    if (hasCritical) {
        return 'Critical phishing indicators detected. This website is highly suspicious.';
    } else if (hasWarning) {
        return 'Some phishing indicators detected. Exercise caution.';
    } else if (flags.length > 0) {
        return 'Minor concerns detected. Website appears mostly legitimate.';
    } else {
        return 'No significant concerns detected.';
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

    // Calculate total score
    let totalScore = 0;
    totalScore += heuristic?.score || 0;
    totalScore += typosquatting?.score || 0;
    totalScore += ssl?.score || 0;
    totalScore += whois?.score || 0;
    totalScore += content?.score || 0;
    totalScore += reputation?.score || 0;

    // If hosted platform but has typosquatting, increase score
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
            heuristic: heuristic?.score || 0,
            typosquatting: typosquatting?.score || 0,
            ssl: ssl?.score || 0,
            domainAge: whois?.score || 0,
            content: content?.score || 0,
            reputation: reputation?.score || 0,
            total: Math.min(totalScore, 100)
        }
    };
};

module.exports = {
    calculateVerdict,
    generateSummary,
    combineResults
};