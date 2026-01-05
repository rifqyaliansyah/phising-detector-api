const express = require('express');
const router = express.Router();

const { isValidUrl, sanitizeUrl } = require('../utils/validator');
const { isWhitelisted } = require('../config/whitelist');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

// Services
const { parseUrl } = require('../services/parser.service');
const { analyzeUrl } = require('../services/heuristic.service');
const { detectTyposquatting } = require('../services/typosquatting.service');
const { checkSSL } = require('../services/ssl.service');
const { checkDomainAge } = require('../services/whois.service');
const { analyzeContent } = require('../services/content.service');
const { checkReputation } = require('../services/reputation.service');
const { combineResults } = require('../services/scoring.service');

// Main check endpoint
router.post('/check', async (req, res) => {
    try {
        let { url } = req.body;

        // Validate input
        if (!url) {
            return res.status(400).json({
                success: false,
                error: 'URL is required'
            });
        }

        // Sanitize URL
        url = sanitizeUrl(url);

        // Validate URL format
        const validation = isValidUrl(url);
        if (!validation.valid) {
            return res.status(400).json({
                success: false,
                error: validation.error
            });
        }

        url = validation.url;

        // Check cache
        const cacheKey = `check:${url}`;
        const cachedResult = cache.get(cacheKey);
        if (cachedResult) {
            logger.info(`Cache hit for ${url}`);
            return res.json({
                success: true,
                cached: true,
                data: cachedResult
            });
        }

        // Parse URL
        const parsedUrl = parseUrl(url);
        if (!parsedUrl.success) {
            return res.status(400).json({
                success: false,
                error: 'Failed to parse URL'
            });
        }

        // Check whitelist first
        if (isWhitelisted(parsedUrl.hostname)) {
            logger.info(`Whitelisted domain: ${parsedUrl.hostname}`);
            const safeResult = {
                url: parsedUrl.url,
                verdict: 'SAFE',
                riskScore: 0,
                level: 'success',
                summary: 'Domain is in the trusted whitelist.',
                recommendation: 'This domain is verified as safe.',
                flags: ['WHITELISTED'],
                analysis: {
                    domain: {
                        hostname: parsedUrl.hostname,
                        rootDomain: parsedUrl.rootDomain,
                        isHostedPlatform: parsedUrl.isHostedPlatform
                    }
                },
                scores: { total: 0 }
            };

            cache.set(cacheKey, safeResult);
            return res.json({
                success: true,
                data: safeResult
            });
        }

        logger.info(`Analyzing URL: ${url}`);

        // Run all checks in parallel
        const [
            heuristic,
            typosquatting,
            ssl,
            whois,
            content,
            reputation
        ] = await Promise.all([
            analyzeUrl(parsedUrl),
            detectTyposquatting(parsedUrl),
            checkSSL(parsedUrl),
            parsedUrl.isHostedPlatform ? Promise.resolve(null) : checkDomainAge(parsedUrl.rootDomain),
            analyzeContent(url, parsedUrl),
            checkReputation(parsedUrl)
        ]);

        // Combine results
        const result = combineResults({
            parsedUrl,
            heuristic,
            typosquatting,
            ssl,
            whois,
            content,
            reputation
        });

        // Cache result
        cache.set(cacheKey, result);

        logger.info(`Analysis complete for ${url}: ${result.verdict} (${result.riskScore})`);

        res.json({
            success: true,
            data: result
        });
    } catch (error) {
        logger.error('Check endpoint error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Health check
router.get('/health', (req, res) => {
    const cacheStats = cache.stats();
    res.json({
        success: true,
        status: 'healthy',
        cache: cacheStats
    });
});

module.exports = router;