const NodeCache = require('node-cache');

// Cache TTL dari env (default 1 jam)
const CACHE_TTL = parseInt(process.env.CACHE_TTL || 3600);

// Init cache
const cache = new NodeCache({
    stdTTL: CACHE_TTL,
    checkperiod: 120, // Check expired keys every 2 minutes
    useClones: false
});

// Get from cache
const get = (key) => {
    return cache.get(key);
};

// Set to cache
const set = (key, value, ttl = CACHE_TTL) => {
    return cache.set(key, value, ttl);
};

// Delete from cache
const del = (key) => {
    return cache.del(key);
};

// Clear all cache
const flush = () => {
    return cache.flushAll();
};

// Get cache stats
const stats = () => {
    return cache.getStats();
};

module.exports = {
    get,
    set,
    del,
    flush,
    stats
};