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
            validateStatus: (status) => status < 500, // Accept 4xx responses
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
                score += 20;
                flags.push('PASSWORD_FORM');

                // 3. Check form action
                forms.each((i, form) => {
                    const action = $(form).attr('action');
                    if (action) {
                        try {
                            const actionUrl = new URL(action, url);
                            if (actionUrl.hostname !== parsedUrl.hostname) {
                                score += 25;
                                flags.push('EXTERNAL_FORM_ACTION');
                                details.externalFormAction = actionUrl.hostname;
                            }
                        } catch (e) {
                            // Invalid action URL
                        }
                    }
                });
            }
        }

        // 4. Check for sensitive keywords in text
        const bodyText = $('body').text().toLowerCase();
        const sensitiveKeywords = [
            'password', 'credit card', 'ssn', 'social security',
            'cvv', 'pin', 'verify account', 'confirm identity',
            'urgent', 'suspended', 'unusual activity'
        ];

        const foundKeywords = sensitiveKeywords.filter(kw => bodyText.includes(kw));
        if (foundKeywords.length > 2) {
            score += 15;
            flags.push('SENSITIVE_CONTENT');
            details.sensitiveKeywords = foundKeywords.slice(0, 5);
        }

        // 5. Check title for brand impersonation
        const title = $('title').text();
        details.title = title;

        // 6. Check for iframes
        const iframes = $('iframe');
        if (iframes.length > 3) {
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
        if (externalLinkRatio > 0.8 && links.length > 5) {
            score += 10;
            flags.push('HIGH_EXTERNAL_LINKS');
        }

        details.totalLinks = links.length;
        details.externalLinks = externalLinkCount;

        // 8. Check for redirect
        if (hasRedirect) {
            score += 10;
            flags.push('HAS_REDIRECT');
            details.finalUrl = redirectChain;
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