'use strict';

const winston = require('winston');
const path    = require('path');
const fs      = require('fs');

const logsDir = process.env.LOGS_DIR || path.join(__dirname, '../logs');
const isDev   = process.env.NODE_ENV !== 'production';

// Ensure logs directory exists (needed on first run and in AWS containers)
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const consoleTransport = new winston.transports.Console({
  format: isDev
    ? winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({ format: 'HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const extras = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
          return `${timestamp} [${level}] ${message}${extras}`;
        })
      )
    : winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()   // CloudWatch Logs Insights auto-indexes JSON fields
      )
});

const fileTransport = new winston.transports.File({
  filename: path.join(logsDir, 'app.log'),
  maxsize:  10 * 1024 * 1024,  // 10 MB, then rotate
  maxFiles: 3,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json())
});

module.exports = winston.createLogger({
  level:       process.env.LOG_LEVEL || 'info',
  transports:  [consoleTransport, fileTransport],
  exitOnError: false
});
