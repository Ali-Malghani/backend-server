const axios = require('axios');
const logger = require('../utils/logger');

/**
 * Fetches domain age in days using an external WHOIS API.
 * Requires WHOIS_API_KEY in .env
 * @param {string} domain 
 * @returns {Promise<number>} days since registration
 */
const getDomainAge = async (domain) => {
  const apiKey = process.env.WHOIS_API_KEY;
  if (!apiKey) {
    logger.warn('WHOIS_API_KEY not found. Returning default age (-1).');
    return -1; // Return -1 for unknown/unavailable
  }

  // Standardize domain
  const hostname = domain.replace(/^https?:\/\//, '').split('/')[0];

  try {
    // Example using WhoisXMLAPI (common choice)
    const response = await axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService`, {
      params: {
        apiKey: apiKey,
        domainName: hostname,
        outputFormat: 'JSON'
      }
    });

    const createdDate = response.data?.WhoisRecord?.createdDate;
    if (!createdDate) {
      logger.warn(`Could not find creation date for ${hostname}`);
      return -1; // Return -1 for unknown age
    }

    const created = new Date(createdDate);
    const now = new Date();
    const diffTime = Math.abs(now - created);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    logger.info(`Domain age for ${hostname}: ${diffDays} days`);
    return diffDays;

  } catch (error) {
    logger.error(`WHOIS API error for ${hostname}: ${error.message}`);
    // Return -1 for API failure to distinguish from actual 0-age domains
    return -1;
  }
};

module.exports = { getDomainAge };
