const tldts = require('tldts');

// Hosted platform domains
const HOSTED_PLATFORMS = [
    'vercel.app',
    'netlify.app',
    'github.io',
    'pages.dev',
    'firebaseapp.com',
    'herokuapp.com',
    'azurewebsites.net',
    'web.app',
    'railway.app',
    'render.com',
    'fly.dev',
    'onrender.com',
    'replit.app',
    'glitch.me',
    '000webhostapp.com',
    'wixsite.com',
    'wordpress.com',
    'blogspot.com',
    'weebly.com',
    'webflow.io',
    'carrd.co'
];

const parseUrl = (urlString) => {
    try {
        const url = new URL(urlString);
        const parsed = tldts.parse(urlString);

        const hostname = url.hostname.toLowerCase();
        const rootDomain = (parsed.domain || hostname).toLowerCase();
        const subdomain = parsed.subdomain || '';

        // Check if hosted platform
        const isHostedPlatform = HOSTED_PLATFORMS.some(platform =>
            rootDomain === platform || hostname.endsWith('.' + platform)
        );

        return {
            success: true,
            url: url.href,
            protocol: url.protocol.replace(':', ''),
            hostname,
            rootDomain,
            subdomain,
            pathname: url.pathname,
            search: url.search,
            isHostedPlatform,
            platform: isHostedPlatform ? rootDomain : null
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
};

module.exports = {
    parseUrl,
    HOSTED_PLATFORMS
};