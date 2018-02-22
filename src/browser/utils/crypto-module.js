window.Module = window.Module || {};
window.Module.ENVIRONMENT = 'WEB';

require('script!../../lib/virgil_crypto_asmjs');

window.Module.setDelayFunction(function (fn) {
	setTimeout(fn, 0);
});

export default window.Module;
