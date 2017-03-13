window.Module = window.Module || {};
window.Module.ENVIRONMENT = 'WEB';

require('script!../../lib/virgil-emscripten');

window.Module.setDelayFunction(function (fn) {
	setTimeout(fn, 0);
});

export default window.Module;
