Module = Module || {};
Module.ENVIRONMENT = 'WORKER';
Module.setDelayFunction(function (fn) {
	setTimeout(fn, 0);
});
var VirgilCryptoWorkerContext = Module;
