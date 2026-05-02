const axios = require('axios');
const logger = require('../utils/logger');

/**
 * Checks if a URL is malicious using VirusTotal API.
 * Requires VIRUSTOTAL_API_KEY in .env
 * @param {string} url
 * @returns {Promise<boolean>} true if malicious, false otherwise
 */
const checkMaliciousVT = async (url) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
        logger.warn('VIRUSTOTAL_API_KEY not found. Skipping VirusTotal check.');
        return false;
    }

    try {
        // First, encode the URL for the API
        const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '');

        // Get the URL report
        const response = await axios.get(
            `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
            {
                headers: {
                    'x-apikey': apiKey
                }
            }
        );

        const data = response.data.data.attributes;
        const maliciousCount = data.last_analysis_stats.malicious || 0;
        const totalEngines = data.last_analysis_stats.total || 0;

        const isMalicious = maliciousCount > 0;

        if (isMalicious) {
            logger.warn(`VirusTotal MALICIOUS URL DETECTED: ${url} (${maliciousCount}/${totalEngines} engines)`);
        } else {
            logger.info(`VirusTotal check for ${url}: CLEAN (${maliciousCount}/${totalEngines} engines)`);
        }

        return isMalicious;

    } catch (error) {
        if (error.response && error.response.status === 404) {
            // URL not found in VT database, might need to submit it
            logger.info(`URL not found in VirusTotal database: ${url}. Submitting for analysis.`);
            try {
                const submitResponse = await axios.post(
                    'https://www.virustotal.com/api/v3/urls',
                    `url=${encodeURIComponent(url)}`,
                    {
                        headers: {
                            'x-apikey': apiKey,
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }
                    }
                );

                // After submitting, we can't immediately get results, so return false for now
                logger.info(`Submitted ${url} to VirusTotal for analysis.`);
                return false;
            } catch (submitError) {
                logger.error(`Error submitting URL to VirusTotal: ${submitError.message}`);
                return false;
            }
        } else {
            logger.error(`Error checking VirusTotal: ${error.message}`);
            return false;
        }
    }
};

module.exports = { checkMaliciousVT };
