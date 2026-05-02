const NodeCache = require('node-cache');
const validator = require('validator');
const { checkSSL } = require('../services/sslService');
const { getDomainAge } = require('../services/whoisService');
const { checkMalicious } = require('../services/safeBrowsingService');
const { checkMaliciousVT } = require('../services/virusTotalService');
const logger = require('../utils/logger');

// Cache with 10 minutes TTL (600 seconds)
const cache = new NodeCache({ stdTTL: 600, checkperiod: 120 });

/**
 * Validates and checks the safety of a URL.
 */
const checkUrlSafety = async (req, res, next) => {
  try {
    const { url } = req.body;

    // 1. Validation
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    if (!validator.isURL(url)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // 2. Cache Check
    const cachedResult = cache.get(url);
    if (cachedResult) {
      logger.info(`Cache hit for URL: ${url}`);
      return res.json(cachedResult);
    }

    logger.info(`Processing safety check for: ${url}`);

    // 3. Parallel API Calls for performance
    const [sslStatus, domainAge, isMaliciousGSB, isMaliciousVT] = await Promise.all([
      checkSSL(url),
      getDomainAge(url),
      checkMalicious(url),
      checkMaliciousVT(url)
    ]);

    // 4. Risk Score Calculation (Improved)
    let riskScore = 0;
    let confidence = 0.5; // Default confidence level

    // Malicious checks are critical
    if (isMaliciousGSB || isMaliciousVT) {
      riskScore = 100;
      confidence = 0.95; // High confidence if detected by major services
    } else {
      // If not flagged by malware services, confidence starts higher
      confidence = 0.7;

      // SSL Check - only penalize if definitively invalid
      if (sslStatus === 'invalid') {
        riskScore += 40;
      } else if (sslStatus === 'unknown') {
        // Connection error - don't penalize, unknown state
        riskScore += 5; // Minimal penalty
      }

      // Domain Age Check
      if (domainAge > 0) {
        if (domainAge < 30) { // Less than 1 month - very suspicious
          riskScore += 35;
        } else if (domainAge < 90) { // Less than 3 months
          riskScore += 25;
        } else if (domainAge < 365) { // Less than 1 year
          riskScore += 8;
        }
        // Older domains don't add risk
      } else if (domainAge === -1) {
        // API failed - don't penalize, can't determine
        riskScore += 0;
      }
    }

    // Cap risk score at 100
    riskScore = Math.min(riskScore, 100);

    // Log the results
    console.log("VT result:", isMaliciousVT);
    console.log("GSB result:", isMaliciousGSB);
    console.log("SSL Status:", sslStatus);
    console.log("Domain Age:", domainAge);
    console.log("Risk Score:", riskScore, "Confidence:", confidence);

    const result = {
      url,
      safe: riskScore < 50,
      risk: riskScore,
      confidence: Math.round(confidence * 100), // Confidence as percentage
      sources: {
        virusTotal: isMaliciousVT,
        googleSafeBrowsing: isMaliciousGSB
      },
      details: {
        ssl: sslStatus,
        domainAge: domainAge > -1 ? domainAge : null, // null if unknown
        malicious: isMaliciousGSB || isMaliciousVT
      },
      timestamp: new Date().toISOString()
    };

    // 5. Store in Cache
    cache.set(url, result);

    res.json(result);

  } catch (error) {
    next(error);
  }
};

module.exports = { checkUrlSafety };
