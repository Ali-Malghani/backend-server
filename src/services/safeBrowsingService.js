const axios = require('axios');
const logger = require('../utils/logger');

/**
 * Checks if a URL is malicious using Google Safe Browsing API.
 * Requires SAFE_BROWSING_API_KEY in .env
 * @param {string} url
 * @returns {Promise<boolean>} true if malicious, false otherwise
 */
const checkMalicious = async (url) => {
    const apiKey = process.env.SAFE_BROWSING_API_KEY;
    if (!apiKey) {
        logger.warn('SAFE_BROWSING_API_KEY not found. Skipping malicious check.');
        return false;
    }

    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                client: {
                    clientId: "safety-checker-backend",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"  // fixed typo (was HARMFUR)
                    ],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: url }]
                }
            }
        );

        const isMalicious =
            response.data &&
            response.data.matches &&
            response.data.matches.length > 0;

        if (isMalicious) {
            logger.warn(`MALICIOUS URL DETECTED: ${url}`);
        } else {
            logger.info(`Safe Browsing check for ${url}: CLEAN`);
        }

        return isMalicious;

    } catch (error) {
        logger.error(`Safe Browsing API error: ${error.message}`);
        return false;
    }
};

module.exports = { checkMalicious };
