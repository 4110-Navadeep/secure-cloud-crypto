'use strict';
require('dotenv').config();

module.exports = {
  app: {
    port: Number(process.env.PORT || 5000),
    url: process.env.APP_URL || 'http://localhost:5000',
    nodeEnv: process.env.NODE_ENV || 'development',
  },
};
