const express = require('express');
const router = express.Router();

/**
 * @route GET /health
 * @desc Check if the server is alive
 */
router.get('/', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
