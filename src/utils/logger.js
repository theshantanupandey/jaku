import winston from 'winston';
import path from 'path';
import fs from 'fs';

const LOG_DIR = path.join(process.cwd(), 'jaku-reports', 'logs');

export function createLogger(options = {}) {
  const { verbose = false, logDir = LOG_DIR } = options;

  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const logger = winston.createLogger({
    level: verbose ? 'debug' : 'info',
    format: winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { agent: 'JAKU' },
    transports: [
      new winston.transports.File({
        filename: path.join(logDir, 'jaku-error.log'),
        level: 'error',
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'jaku-audit.log'),
      }),
    ],
  });

  if (process.env.NODE_ENV !== 'production') {
    logger.add(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} [${level}]: ${message}`;
          })
        ),
        silent: !verbose,
      })
    );
  }

  return logger;
}

export default createLogger;
