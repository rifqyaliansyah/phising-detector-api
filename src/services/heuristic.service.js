// String & URL heuristic analysis

const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'validate', 'suspend', 'unusual', 'activity',
    'password', 'reset', 'recover', 'unlock', 'blocked',
    'urgent', 'action', 'required', 'immediately', 'warning',
    'security', 'alert', 'notification', 'verification'
];

const analyzeUrl = (parsedUrl) => {
    const { hostname, pathname, search } = parsedUrl;
    const fullUrl = hostname + pathname + search;

    let score = 0;
    const flags = [];

    // 1. Hostname length check (>50 chars suspicious)
    if (hostname.length > 50) {
        score += 15;
        flags.push('LONG_HOSTNAME');
    }

    // 2. Excessive dashes/hyphens (>3)
    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 3) {
        score += 10;
        flags.push('EXCESSIVE_DASHES');
    }

    // 3. Excessive numbers (>4 digits)
    const digitCount = (hostname.match(/\d/g) || []).length;
    if (digitCount > 4) {
        score += 10;
        flags.push('EXCESSIVE_DIGITS');
    }

    // 4. Suspicious keywords in URL
    const suspiciousKeywords = [];
    for (const keyword of SUSPICIOUS_KEYWORDS) {
        if (fullUrl.toLowerCase().includes(keyword)) {
            suspiciousKeywords.push(keyword);
        }
    }

    if (suspiciousKeywords.length > 0) {
        score += Math.min(suspiciousKeywords.length * 5, 20); // Max 20
        flags.push('SUSPICIOUS_KEYWORDS');
    }

    // 5. @ symbol in URL (phishing trick)
    if (fullUrl.includes('@')) {
        score += 25;
        flags.push('AT_SYMBOL');
    }

    // 6. IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        score += 20;
        flags.push('IP_ADDRESS');
    }

    // 7. Subdomain depth (>3 levels suspicious)
    const subdomainParts = parsedUrl.subdomain.split('.').filter(Boolean);
    if (subdomainParts.length > 3) {
        score += 10;
        flags.push('DEEP_SUBDOMAIN');
    }

    return {
        score,
        flags,
        details: {
            hostnameLength: hostname.length,
            dashCount,
            digitCount,
            suspiciousKeywords,
            subdomainDepth: subdomainParts.length
        }
    };
};

module.exports = {
    analyzeUrl,
    SUSPICIOUS_KEYWORDS
};