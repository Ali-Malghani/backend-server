const express = require('express');
const router = express.Router();
const { checkUrlSafety } = require('../controllers/checkController');
const { apiLimiter } = require('../middleware/rateLimiter');

/**
 * @route POST /check
 * @desc Analyze a URL for safety
 * @access Public (with rate limiting)
 */
router.post('/', apiLimiter, checkUrlSafety);

module.exports = router;
