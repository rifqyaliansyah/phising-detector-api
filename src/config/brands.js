// Brand list untuk typosquatting detection
// Top brands di Indonesia + International

const BRANDS = [
    // E-commerce Indonesia
    'tokopedia', 'shopee', 'bukalapak', 'lazada', 'blibli', 'jd.id',

    // Banking Indonesia
    'bca', 'mandiri', 'bni', 'bri', 'cimb', 'danamon', 'permata', 'ocbc', 'maybank',
    'jenius', 'flip', 'ovo', 'gopay', 'dana', 'linkaja', 'shopeepay',

    // Social Media & Tech
    'google', 'facebook', 'instagram', 'twitter', 'tiktok', 'whatsapp', 'telegram',
    'youtube', 'linkedin', 'microsoft', 'apple', 'amazon',

    // Payment & Finance
    'paypal', 'stripe', 'visa', 'mastercard', 'american express', 'discover',

    // Crypto
    'binance', 'coinbase', 'crypto.com', 'indodax', 'tokocrypto',

    // Gaming & Entertainment
    'steam', 'epic games', 'roblox', 'minecraft', 'netflix', 'spotify', 'disney',

    // Logistics
    'jne', 'jnt', 'sicepat', 'anteraja', 'gosend', 'grabexpress',

    // Government
    'pajak', 'bpjs', 'kemenkes', 'polri', 'kemenkeu',

    // Airlines
    'garuda', 'lionair', 'citilink', 'airasia', 'batik air'
];

// Character substitutions untuk typosquatting
const TYPO_CHARS = {
    '0': ['o', 'O'],
    '1': ['l', 'I', 'i'],
    '3': ['e', 'E'],
    '4': ['a', 'A'],
    '5': ['s', 'S'],
    '8': ['b', 'B'],
    '@': ['a'],
    'rn': ['m'],
    'vv': ['w'],
    'cl': ['d']
};

// Get brands from env (optional extension)
const getCustomBrands = () => {
    const customBrands = process.env.CUSTOM_BRANDS || '';
    return customBrands.split(',').map(b => b.trim().toLowerCase()).filter(Boolean);
};

const getAllBrands = () => {
    return [...new Set([...BRANDS, ...getCustomBrands()])];
};

module.exports = {
    BRANDS: getAllBrands(),
    TYPO_CHARS
};