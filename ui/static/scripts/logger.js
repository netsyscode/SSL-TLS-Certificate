

import sprintf from 'sprintf-js';
import winston from 'winston';
import path from 'path';

const logFilePath = path.join(__dirname, 'log', 'logfile.log');

// 创建一个logger实例
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: logFilePath }),
    new winston.transports.Console()
  ]
});

export default logger;
logger.info(sprintf('Hello, Winston! Log file is at %s', logFilePath));
