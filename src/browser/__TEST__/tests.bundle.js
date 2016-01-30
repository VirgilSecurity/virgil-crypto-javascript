import 'babel-core/external-helpers';

let tests = require.context('./', true, /.+\.spec\.js$/);
tests.keys().forEach(tests);

export default tests;
