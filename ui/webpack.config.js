const path = require('path');

module.exports = {
  entry: './static/scripts/system/scan.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
};
