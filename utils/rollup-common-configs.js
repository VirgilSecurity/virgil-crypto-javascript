const copy = require('rollup-plugin-copy');
const { getOutputFilename } = require('./build');
const declarationTemplatePath = require.resolve('./declaration.d.ts.template');

console.log('declarationTemplatePath', declarationTemplatePath);

const createDeclarationForInnerEntry = (target, cryptoType, format, outputDir) =>
  copy({
    targets: [
      {
        src: declarationTemplatePath,
        dest: outputDir,
        rename: getOutputFilename(target, cryptoType, format, 'd.ts'),
      },
    ],
  });

module.exports = {
  createDeclarationForInnerEntry,
};
