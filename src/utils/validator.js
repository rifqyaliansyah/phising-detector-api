// Input validation utilities

const isValidUrl = (urlString) => {
    try {
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'https://' + urlString;
        }

        const url = new URL(urlString);

        if (!url.hostname) {
            return { valid: false, error: 'Invalid hostname' };
        }

        if (isPrivateIP(url.hostname)) {
            return { valid: false, error: 'Private IP addresses are not allowed' };
        }

        return { valid: true, url: url.href };
    } catch (error) {
        return { valid: false, error: 'Invalid URL format' };
    }
};

const isPrivateIP = (hostname) => {
    const privateIPPatterns = [
        /^127\./,           // localhost
        /^10\./,            // 10.x.x.x
        /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.x.x - 172.31.x.x
        /^192\.168\./,      // 192.168.x.x
        /^localhost$/i,
        /^0\.0\.0\.0$/
    ];

    return privateIPPatterns.some(pattern => pattern.test(hostname));
};

const sanitizeUrl = (url) => {
    // Remove trailing slashes, whitespace
    return url.trim().replace(/\/+$/, '');
};

module.exports = {
    isValidUrl,
    isPrivateIP,
    sanitizeUrl
};