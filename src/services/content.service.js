const axios = require('axios');
const cheerio = require('cheerio');
const logger = require('../utils/logger');

const TIMEOUT = parseInt(process.env.TIMEOUT_CONTENT || 8000);

const analyzeContent = async (url, parsedUrl) => {
    try {
        // Fetch HTML content
        const response = await axios.get(url, {
            timeout: TIMEOUT,
            maxRedirects: 5,
            validateStatus: (status) => status < 500,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        // Check redirect chain
        const redirectChain = response.request?.res?.responseUrl;
        const hasRedirect = redirectChain && redirectChain !== url;

        if (response.status >= 400) {
            return {
                success: false,
                score: 5,
                flags: ['HTTP_ERROR'],
                details: {
                    statusCode: response.status,
                    error: `HTTP ${response.status}`
                }
            };
        }

        const html = response.data;
        const $ = cheerio.load(html);

        let score = 0;
        const flags = [];
        const details = {};

        // 1. Check for forms
        const forms = $('form');
        const hasForms = forms.length > 0;
        details.formCount = forms.length;

        if (hasForms) {
            // 2. Check for password inputs
            const passwordInputs = $('input[type="password"]');
            const hasPasswordInput = passwordInputs.length > 0;
            details.hasPasswordInput = hasPasswordInput;

            if (hasPasswordInput) {
                // SMART PASSWORD FORM DETECTION:
                // Only flag as suspicious if combined with other red flags

                // Check if domain is new (will be combined in scoring)
                // For now, just add a small score that can be weighted later
                score += 5; // Reduced from 20
                flags.push('PASSWORD_FORM');

                // 3. Check form action - THIS IS MORE IMPORTANT
                let hasExternalForm = false;
                forms.each((i, form) => {
                    const action = $(form).attr('action');
                    if (action) {
                        try {
                            const actionUrl = new URL(action, url);
                            if (actionUrl.hostname !== parsedUrl.hostname) {
                                score += 30; // Increased from 25 - very suspicious!
                                flags.push('EXTERNAL_FORM_ACTION');
                                details.externalFormAction = actionUrl.hostname;
                                hasExternalForm = true;
                            }
                        } catch (e) {
                            // Invalid action URL
                        }
                    }
                });

                // If password form + external action, increase score
                if (hasExternalForm) {
                    score += 15; // Extra penalty for password + external form
                }
            }
        }

        // 4. Check for sensitive keywords in text
        const bodyText = $('body').text().toLowerCase();
        const phishingKeywords = [
            'verify account', 'confirm identity', 'suspended account',
            'unusual activity', 'click here immediately', 'urgent action required',
            'account will be closed', 'update payment', 'verify payment method'
        ];

        const normalKeywords = [
            'password', 'credit card', 'login', 'sign in'
        ];

        const foundPhishingKeywords = phishingKeywords.filter(kw => bodyText.includes(kw));
        const foundNormalKeywords = normalKeywords.filter(kw => bodyText.includes(kw));

        // Only flag if actual phishing language is used
        if (foundPhishingKeywords.length >= 2) {
            score += 20; // Increased from 15
            flags.push('PHISHING_LANGUAGE');
            details.phishingKeywords = foundPhishingKeywords.slice(0, 5);
        } else if (foundNormalKeywords.length > 3 && foundPhishingKeywords.length > 0) {
            // Combination of normal + some phishing language
            score += 10;
            flags.push('SUSPICIOUS_LANGUAGE');
            details.suspiciousKeywords = [...foundPhishingKeywords, ...foundNormalKeywords].slice(0, 5);
        }

        // 5. Check title
        const title = $('title').text();
        details.title = title;

        // Check for brand impersonation in title
        const brandKeywords = ['paypal', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 'netflix', 'bank'];
        const titleLower = title.toLowerCase();
        const hasBrandInTitle = brandKeywords.some(brand => titleLower.includes(brand));

        if (hasBrandInTitle && parsedUrl.rootDomain) {
            const domainLower = parsedUrl.rootDomain.toLowerCase();
            const isBrandDomain = brandKeywords.some(brand => domainLower.includes(brand));

            // If title has brand name but domain doesn't match
            if (!isBrandDomain) {
                score += 15;
                flags.push('BRAND_MISMATCH');
                details.brandMismatch = true;
            }
        }

        // 6. Check for excessive iframes
        const iframes = $('iframe');
        if (iframes.length > 5) { // Increased threshold
            score += 10;
            flags.push('EXCESSIVE_IFRAMES');
            details.iframeCount = iframes.length;
        }

        // 7. Check external links
        const links = $('a[href]');
        let externalLinkCount = 0;
        links.each((i, link) => {
            const href = $(link).attr('href');
            if (href && href.startsWith('http')) {
                try {
                    const linkUrl = new URL(href);
                    if (linkUrl.hostname !== parsedUrl.hostname) {
                        externalLinkCount++;
                    }
                } catch (e) {
                    // Invalid URL
                }
            }
        });

        const externalLinkRatio = links.length > 0 ? externalLinkCount / links.length : 0;

        // More lenient - most legitimate sites have external links
        if (externalLinkRatio > 0.9 && links.length > 10) {
            score += 8;
            flags.push('EXCESSIVE_EXTERNAL_LINKS');
        }

        details.totalLinks = links.length;
        details.externalLinks = externalLinkCount;

        // 8. Check for suspicious redirects
        if (hasRedirect) {
            // Only flag if redirect goes to different domain
            try {
                const originalHost = new URL(url).hostname;
                const finalHost = new URL(redirectChain).hostname;

                if (originalHost !== finalHost) {
                    score += 15;
                    flags.push('CROSS_DOMAIN_REDIRECT');
                    details.redirectedTo = finalHost;
                } else {
                    // Same domain redirect is usually fine (http -> https, www, etc)
                    details.hasRedirect = true;
                }
            } catch (e) {
                // Can't parse URLs
            }
        }

        // 9. Check for hidden elements with forms (common phishing technique)
        const hiddenForms = $('form[style*="display:none"], form[style*="display: none"]');
        if (hiddenForms.length > 0) {
            score += 20;
            flags.push('HIDDEN_FORM');
            details.hiddenFormCount = hiddenForms.length;
        }

        return {
            success: true,
            score,
            flags,
            details
        };
    } catch (error) {
        logger.warn(`Content analysis failed for ${url}:`, error.message);

        return {
            success: false,
            score: 0,
            flags: ['CONTENT_CHECK_FAILED'],
            details: {
                error: error.message
            }
        };
    }
};

module.exports = {
    analyzeContent
};