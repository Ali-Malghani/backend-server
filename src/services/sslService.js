const tls = require('tls');
const logger = require('../utils/logger');

/**
 * Checks if a domain has a valid SSL certificate.
 * @param {string} domain 
 * @returns {Promise<string>} 'valid' | 'invalid'
 */
const checkSSL = (domain) => {
  return new Promise((resolve) => {
    // Standardize domain (remove protocol/path if present)
    const hostname = domain.replace(/^https?:\/\//, '').split('/')[0];

    const options = {
      hostname: hostname,
      port: 443,
      method: 'GET',
      rejectUnauthorized: true // This is the key check
    };

    try {
      const socket = tls.connect(options, () => {
        try {
          const cert = socket.getPeerCertificate();
          if (socket.authorized && cert && cert.valid_from) {
            logger.info(`SSL check for ${hostname}: VALID`);
            socket.end();
            resolve('valid');
          } else if (cert && cert.valid_from) {
            // Certificate exists but authorization failed - likely self-signed or cert issue
            logger.warn(`SSL check for ${hostname}: INVALID (${socket.authorizationError})`);
            socket.end();
            resolve('invalid');
          } else {
            // No valid certificate
            logger.warn(`SSL check for ${hostname}: NO CERTIFICATE`);
            socket.end();
            resolve('no_cert');
          }
        } catch (certError) {
          logger.error(`SSL certificate parse error for ${hostname}: ${certError.message}`);
          socket.end();
          resolve('no_cert');
        }
      });

      socket.on('error', (err) => {
        // Connection errors don't necessarily mean SSL is invalid
        // Could be network issues, timeout, etc.
        logger.warn(`SSL check connection error for ${hostname}: ${err.message}`);
        socket.destroy();
        // Return 'unknown' instead of 'invalid' for connection errors
        resolve('unknown');
      });

      // Timeout after 5 seconds
      socket.setTimeout(5000);
      socket.on('timeout', () => {
        logger.warn(`SSL check timeout for ${hostname}`);
        socket.destroy();
        resolve('unknown');
      });

    } catch (error) {
      logger.error(`SSL service exception: ${error.message}`);
      resolve('unknown');
    }
  });
};

module.exports = { checkSSL };
