const path = require('path');

const HtmlWebpackPlugin = require('html-webpack-plugin');

const sourceRoot = path.join(__dirname, 'src');

module.exports = {
  mode: 'development',
  entry: path.join(sourceRoot, 'index.js'),
  module: {
    rules: [
      {
        test: /\.wasm$/,
        type: 'javascript/auto',
        loader: 'file-loader',
        options: {
          name: '[name].[ext]',
        },
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({ template: path.join(sourceRoot, 'index.html') }),
    // new BundleAnalyzerPlugin(),
  ],
};
