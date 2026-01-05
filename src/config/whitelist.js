// Whitelist untuk domain yang pasti aman (false positive prevention)

const WHITELIST_DOMAINS = [
    // Indonesian E-commerce
    'tokopedia.com', 'tokopedia.net',
    'shopee.co.id', 'shopee.com',
    'bukalapak.com', 'bukalapak.io',
    'lazada.co.id',
    'blibli.com',

    // Banking
    'klikbca.com', 'bca.co.id',
    'bankmandiri.co.id',
    'bni.co.id',
    'bri.co.id',

    // Tech Giants
    'google.com', 'google.co.id', 'youtube.com',
    'facebook.com', 'fb.com', 'instagram.com',
    'microsoft.com', 'live.com', 'outlook.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'aws.amazon.com',

    // Payment
    'gopay.co.id', 'gojek.com',
    'ovo.id',
    'dana.id',
    'shopeepay.co.id',
    'paypal.com',

    // Government
    'go.id', 'pajak.go.id', 'bpjs-kesehatan.go.id'
];

// Wildcard patterns (untuk subdomain)
const WHITELIST_PATTERNS = [
    /^.*\.google\.com$/,
    /^.*\.googleapis\.com$/,
    /^.*\.youtube\.com$/,
    /^.*\.facebook\.com$/,
    /^.*\.instagram\.com$/,
    /^.*\.microsoft\.com$/,
    /^.*\.apple\.com$/,
    /^.*\.amazon\.com$/,
    /^.*\.tokopedia\.com$/,
    /^.*\.shopee\.co\.id$/,
    /^.*\.bukalapak\.com$/,
    /^.*\.go\.id$/
];

const isWhitelisted = (hostname) => {
    hostname = hostname.toLowerCase();

    // Check exact match
    if (WHITELIST_DOMAINS.includes(hostname)) {
        return true;
    }

    // Check pattern match
    for (const pattern of WHITELIST_PATTERNS) {
        if (pattern.test(hostname)) {
            return true;
        }
    }

    return false;
};

module.exports = {
    WHITELIST_DOMAINS,
    WHITELIST_PATTERNS,
    isWhitelisted
};