const path = require('path');
const fs = require('fs');

const _ = require('lodash');

const templatesPath = path.join(__dirname, 'templates');
const outputPath = path.join(__dirname, 'dist');

const cjsTemplateContent = fs.readFileSync(path.join(templatesPath, 'cjs.js'));
const esTemplateContent = fs.readFileSync(path.join(templatesPath, 'es.js'));

const filenameTemplates = [
  _.template('browser.asmjs.<%= format %>'),
  _.template('browser.<%= format %>'),
  _.template('node.asmjs.<%= format %>'),
  _.template('node.<%= format %>'),
  _.template('worker.asmjs.<%= format %>'),
  _.template('worker.<%= format %>'),
];

const outputFilePathTemplate = _.template(path.join(outputPath, '<%= filename %>.js'))

const projectModuleTemplate = _.template('@virgilsecurity/core-<%= project %>/<%= filename %>');

const formats = [
  {
    name: 'cjs',
    fileTemplate: _.template(cjsTemplateContent),
  },
  {
    name: 'es',
    fileTemplate: _.template(esTemplateContent),
  },
];

const projectNames = ['foundation', 'phe', 'pythia', 'ratchet'];

if (!fs.existsSync(outputPath)) {
  fs.mkdirSync(outputPath);
}

formats.forEach(format => {
  filenameTemplates.forEach(filenameTemplate => {
    const filename = filenameTemplate({ format: format.name });
    const modules = projectNames.reduce((result, project) => {
      result[project] = projectModuleTemplate({ project, filename });
      return result;
    }, {});
    const outputFilePath = outputFilePathTemplate({ filename });
    fs.writeFileSync(outputFilePath, format.fileTemplate(modules));
  });
});
