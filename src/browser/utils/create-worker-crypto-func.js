import 'operative';
import blobScript from './blob-script';
import rawVirgilEmscripten from 'raw!../../lib/virgil-emscripten';
import rawWorkerCrypto from 'raw!./worker-crypto-context';

export function createWorkerCryptoFunc (func) {
	return window.operative(func, [blobScript(rawVirgilEmscripten), blobScript(rawWorkerCrypto)]);
}

export default createWorkerCryptoFunc;
