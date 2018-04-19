const path = require('path');
const fs = require('fs');

// code borrowed from webpack script-loader
// see: https://github.com/webpack-contrib/script-loader/blob/master/addScript.js
const HELPERS = `
	/*
		MIT License http://www.opensource.org/licenses/mit-license.php
		Author Tobias Koppers @sokra
	*/
	export function addScript(src) {
	function log(error) {
		(typeof console !== "undefined")
		&& (console.error || console.log)("[global-script]", error);
	}

	// Check for IE =< 8
	function isIE() {
		return typeof attachEvent !== "undefined" && typeof addEventListener === "undefined";
	}

	try {
		if (typeof execScript !== "undefined" && isIE()) {
			execScript(src);
		} else if (typeof eval !== "undefined") {
			eval.call(null, src);
		} else {
			log("EvalError: No eval function available");
		}
	} catch (error) {
		log(error);
	}
}
`;

const HELPERS_ID = '\0global-script-helpers';
const PREFIX = '\0global-script-proxy:';

function globalScript(moduleId) {
	const resolvedModuleId = path.resolve(moduleId);

	return {
		name: 'global-script',

		resolveId(importee, importer) {
			if ( importee === HELPERS_ID ) {
				return importee;
			}

			if (importee === moduleId) {
				return PREFIX + importee;
			}

			if (importer) {
				if (importer.startsWith(PREFIX)){
					importer = importer.slice(PREFIX.length);
				}

				const resolved = path.resolve(path.dirname(importer), importee);
				if (resolved === resolvedModuleId) {
					return PREFIX + resolved;
				}
			}
		},

		load(id) {
			if (id === HELPERS_ID) {
				return HELPERS;
			}

			if (id.startsWith(PREFIX)) {
				id = id.slice(PREFIX.length);

				const code = fs.readFileSync(id, { encoding: 'utf8' });

				const transformedCode = `
					import { addScript } from '${HELPERS_ID}';
					addScript(${JSON.stringify(code)});
				`;

				return {
					code: transformedCode,
					map: { mappings: '' }
				};
			}
		}
	};
}

module.exports = globalScript;
