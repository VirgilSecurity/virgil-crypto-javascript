"use strict";function e(e){return e&&e.__esModule&&Object.prototype.hasOwnProperty.call(e,"default")?e.default:e}var t={exports:{}};!function(e,t){var r,a=(r="undefined"!=typeof document&&document.currentScript?document.currentScript.src:void 0,"undefined"!=typeof __filename&&(r=r||__filename),function(e={}){var t,r,a=e;a.ready=new Promise(((e,a)=>{t=e,r=a}));var n,o,s,i=Object.assign({},a),_=(e,t)=>{throw t},c=require("fs"),f=require("path");n=__dirname+"/",o=e=>(e=H(e)?new URL(e):f.normalize(e),c.readFileSync(e,void 0)),s=e=>((e=o(e)).buffer||(e=new Uint8Array(e)),e),process.argv.slice(2),_=(e,t)=>{throw process.exitCode=e,t},a.inspect=()=>"[Emscripten Module object]";var u,l=a.print||console.log.bind(console),d=a.printErr||console.error.bind(console);Object.assign(a,i),i=null,a.quit&&(_=a.quit),a.wasmBinary&&(u=a.wasmBinary),"object"!=typeof WebAssembly&&S("no native wasm support detected");var v,h,p,y,w,m,b,E=!1;function g(){var e=v.buffer;a.HEAP8=p=new Int8Array(e),a.HEAP16=w=new Int16Array(e),a.HEAPU8=y=new Uint8Array(e),a.HEAPU16=new Uint16Array(e),a.HEAP32=m=new Int32Array(e),a.HEAPU32=b=new Uint32Array(e),a.HEAPF32=new Float32Array(e),a.HEAPF64=new Float64Array(e)}var P=[],A=[],k=[];function B(){var e=a.preRun.shift();P.unshift(e)}var T=0,x=null;function S(e){throw a.onAbort?.(e),d(e="Aborted("+e+")"),E=!0,h=1,e=new WebAssembly.RuntimeError(e+". Build with -sASSERTIONS for more info."),r(e),e}var L,R,z,H=e=>e.startsWith("file://");if(!(L="libpythia.wasm").startsWith("data:application/octet-stream;base64,")){var N=L;L=a.locateFile?a.locateFile(N,n):n+N}function M(e,t){return function(){var e=L;return Promise.resolve().then((()=>{if(e==L&&u)var t=new Uint8Array(u);else{if(!s)throw"both async and sync fetching of the wasm failed";t=s(e)}return t}))}().then((t=>WebAssembly.instantiate(t,e))).then((e=>e)).then(t,(e=>{d(`failed to asynchronously prepare wasm: ${e}`),S(e)}))}function U(e){this.name="ExitStatus",this.message=`Program terminated with exit(${e})`,this.status=e}var C,D=e=>{for(;0<e.length;)e.shift()(a)},Y=a.noExitRuntime||!0,I=(e,t)=>{for(var r=0,a=e.length-1;0<=a;a--){var n=e[a];"."===n?e.splice(a,1):".."===n?(e.splice(a,1),r++):r&&(e.splice(a,1),r--)}if(t)for(;r;r--)e.unshift("..");return e},$=e=>{var t="/"===e.charAt(0),r="/"===e.substr(-1);return(e=I(e.split("/").filter((e=>!!e)),!t).join("/"))||t||(e="."),e&&r&&(e+="/"),(t?"/":"")+e},F=e=>{var t=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(e).slice(1);return e=t[0],t=t[1],e||t?(t&&=t.substr(0,t.length-1),e+t):"."},K=e=>{if("/"===e)return"/";var t=(e=(e=$(e)).replace(/\/$/,"")).lastIndexOf("/");return-1===t?e:e.substr(t+1)},j=e=>(j=(()=>{if("object"==typeof crypto&&"function"==typeof crypto.getRandomValues)return e=>crypto.getRandomValues(e);try{var e=require("crypto");if(e.randomFillSync)return t=>e.randomFillSync(t);var t=e.randomBytes;return e=>(e.set(t(e.byteLength)),e)}catch(e){}S("initRandomDevice")})())(e);function O(){for(var e="",t=!1,r=arguments.length-1;-1<=r&&!t;r--){if("string"!=typeof(t=0<=r?arguments[r]:"/"))throw new TypeError("Arguments to path.resolve must be strings");if(!t)return"";e=t+"/"+e,t="/"===t.charAt(0)}return(t?"/":"")+(e=I(e.split("/").filter((e=>!!e)),!t).join("/"))||"."}var W="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0,V=(e,t)=>{for(var r=t+NaN,a=t;e[a]&&!(a>=r);)++a;if(16<a-t&&e.buffer&&W)return W.decode(e.subarray(t,a));for(r="";t<a;){var n=e[t++];if(128&n){var o=63&e[t++];if(192==(224&n))r+=String.fromCharCode((31&n)<<6|o);else{var s=63&e[t++];65536>(n=224==(240&n)?(15&n)<<12|o<<6|s:(7&n)<<18|o<<12|s<<6|63&e[t++])?r+=String.fromCharCode(n):(n-=65536,r+=String.fromCharCode(55296|n>>10,56320|1023&n))}}else r+=String.fromCharCode(n)}return r},q=[],G=[];function J(e,t){G[e]={input:[],output:[],Ba:t},Pe(e,Q)}var Q={open(e){var t=G[e.node.rdev];if(!t)throw new ce(43);e.tty=t,e.seekable=!1},close(e){e.tty.Ba.fsync(e.tty)},fsync(e){e.tty.Ba.fsync(e.tty)},read(e,t,r,a){if(!e.tty||!e.tty.Ba.Pa)throw new ce(60);for(var n=0,o=0;o<a;o++){try{var s=e.tty.Ba.Pa(e.tty)}catch(e){throw new ce(29)}if(void 0===s&&0===n)throw new ce(6);if(null==s)break;n++,t[r+o]=s}return n&&(e.node.timestamp=Date.now()),n},write(e,t,r,a){if(!e.tty||!e.tty.Ba.Ja)throw new ce(60);try{for(var n=0;n<a;n++)e.tty.Ba.Ja(e.tty,t[r+n])}catch(e){throw new ce(29)}return a&&(e.node.timestamp=Date.now()),n}},X={Pa(){e:{if(!q.length){var e=null,t=Buffer.alloc(256),r=0,a=process.stdin.fd;try{r=c.readSync(a,t)}catch(e){if(!e.toString().includes("EOF"))throw e;r=0}if(!(e=0<r?t.slice(0,r).toString("utf-8"):null)){t=null;break e}for(r=t=0;r<e.length;++r)127>=(a=e.charCodeAt(r))?t++:2047>=a?t+=2:55296<=a&&57343>=a?(t+=4,++r):t+=3;var n=(t=Array(t+1)).length;if(r=0,0<n){a=r,n=r+n-1;for(var o=0;o<e.length;++o){var s=e.charCodeAt(o);if(55296<=s&&57343>=s&&(s=65536+((1023&s)<<10)|1023&e.charCodeAt(++o)),127>=s){if(r>=n)break;t[r++]=s}else{if(2047>=s){if(r+1>=n)break;t[r++]=192|s>>6}else{if(65535>=s){if(r+2>=n)break;t[r++]=224|s>>12}else{if(r+3>=n)break;t[r++]=240|s>>18,t[r++]=128|s>>12&63}t[r++]=128|s>>6&63}t[r++]=128|63&s}}t[r]=0,e=r-a}else e=0;t.length=e,q=t}t=q.shift()}return t},Ja(e,t){null===t||10===t?(l(V(e.output,0)),e.output=[]):0!=t&&e.output.push(t)},fsync(e){e.output&&0<e.output.length&&(l(V(e.output,0)),e.output=[])},Va:()=>({fb:25856,hb:5,eb:191,gb:35387,cb:[3,28,127,21,4,0,1,0,17,19,26,0,18,15,23,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}),Wa:()=>0,Xa:()=>[24,80]},Z={Ja(e,t){null===t||10===t?(d(V(e.output,0)),e.output=[]):0!=t&&e.output.push(t)},fsync(e){e.output&&0<e.output.length&&(d(V(e.output,0)),e.output=[])}};function ee(e,t){var r=e.va?e.va.length:0;r>=t||(t=Math.max(t,r*(1048576>r?2:1.125)>>>0),0!=r&&(t=Math.max(t,256)),r=e.va,e.va=new Uint8Array(t),0<e.xa&&e.va.set(r.subarray(0,e.xa),0))}var te={ya:null,Aa:()=>te.createNode(null,"/",16895,0),createNode(e,t,r,a){if(24576==(61440&r)||4096==(61440&r))throw new ce(63);return te.ya||(te.ya={dir:{node:{Ca:te.ua.Ca,za:te.ua.za,lookup:te.ua.lookup,Fa:te.ua.Fa,rename:te.ua.rename,unlink:te.ua.unlink,rmdir:te.ua.rmdir,readdir:te.ua.readdir,symlink:te.ua.symlink},stream:{Ea:te.wa.Ea}},file:{node:{Ca:te.ua.Ca,za:te.ua.za},stream:{Ea:te.wa.Ea,read:te.wa.read,write:te.wa.write,La:te.wa.La,Qa:te.wa.Qa,Sa:te.wa.Sa}},link:{node:{Ca:te.ua.Ca,za:te.ua.za,readlink:te.ua.readlink},stream:{}},Ma:{node:{Ca:te.ua.Ca,za:te.ua.za},stream:ge}}),16384==(61440&(r=he(e,t,r,a)).mode)?(r.ua=te.ya.dir.node,r.wa=te.ya.dir.stream,r.va={}):32768==(61440&r.mode)?(r.ua=te.ya.file.node,r.wa=te.ya.file.stream,r.xa=0,r.va=null):40960==(61440&r.mode)?(r.ua=te.ya.link.node,r.wa=te.ya.link.stream):8192==(61440&r.mode)&&(r.ua=te.ya.Ma.node,r.wa=te.ya.Ma.stream),r.timestamp=Date.now(),e&&(e.va[t]=r,e.timestamp=r.timestamp),r},ib:e=>e.va?e.va.subarray?e.va.subarray(0,e.xa):new Uint8Array(e.va):new Uint8Array(0),ua:{Ca(e){var t={};return t.dev=8192==(61440&e.mode)?e.id:1,t.ino=e.id,t.mode=e.mode,t.nlink=1,t.uid=0,t.gid=0,t.rdev=e.rdev,16384==(61440&e.mode)?t.size=4096:32768==(61440&e.mode)?t.size=e.xa:40960==(61440&e.mode)?t.size=e.link.length:t.size=0,t.atime=new Date(e.timestamp),t.mtime=new Date(e.timestamp),t.ctime=new Date(e.timestamp),t.Ta=4096,t.blocks=Math.ceil(t.size/t.Ta),t},za(e,t){if(void 0!==t.mode&&(e.mode=t.mode),void 0!==t.timestamp&&(e.timestamp=t.timestamp),void 0!==t.size&&(t=t.size,e.xa!=t))if(0==t)e.va=null,e.xa=0;else{var r=e.va;e.va=new Uint8Array(t),r&&e.va.set(r.subarray(0,Math.min(t,e.xa))),e.xa=t}},lookup(){throw fe[44]},Fa:(e,t,r,a)=>te.createNode(e,t,r,a),rename(e,t,r){if(16384==(61440&e.mode)){try{var a=ve(t,r)}catch(e){}if(a)for(var n in a.va)throw new ce(55)}delete e.parent.va[e.name],e.parent.timestamp=Date.now(),e.name=r,t.va[r]=e,t.timestamp=e.parent.timestamp,e.parent=t},unlink(e,t){delete e.va[t],e.timestamp=Date.now()},rmdir(e,t){var r,a=ve(e,t);for(r in a.va)throw new ce(55);delete e.va[t],e.timestamp=Date.now()},readdir(e){var t,r=[".",".."];for(t of Object.keys(e.va))r.push(t);return r},symlink:(e,t,r)=>((e=te.createNode(e,t,41471,0)).link=r,e),readlink(e){if(40960!=(61440&e.mode))throw new ce(28);return e.link}},wa:{read(e,t,r,a,n){var o=e.node.va;if(n>=e.node.xa)return 0;if(8<(e=Math.min(e.node.xa-n,a))&&o.subarray)t.set(o.subarray(n,n+e),r);else for(a=0;a<e;a++)t[r+a]=o[n+a];return e},write(e,t,r,a,n,o){if(t.buffer===p.buffer&&(o=!1),!a)return 0;if((e=e.node).timestamp=Date.now(),t.subarray&&(!e.va||e.va.subarray)){if(o)return e.va=t.subarray(r,r+a),e.xa=a;if(0===e.xa&&0===n)return e.va=t.slice(r,r+a),e.xa=a;if(n+a<=e.xa)return e.va.set(t.subarray(r,r+a),n),a}if(ee(e,n+a),e.va.subarray&&t.subarray)e.va.set(t.subarray(r,r+a),n);else for(o=0;o<a;o++)e.va[n+o]=t[r+o];return e.xa=Math.max(e.xa,n+a),a},Ea(e,t,r){if(1===r?t+=e.position:2===r&&32768==(61440&e.node.mode)&&(t+=e.node.xa),0>t)throw new ce(28);return t},La(e,t,r){ee(e.node,t+r),e.node.xa=Math.max(e.node.xa,t+r)},Qa(e,t,r,a,n){if(32768!=(61440&e.node.mode))throw new ce(43);if(e=e.node.va,2&n||e.buffer!==p.buffer){if((0<r||r+t<e.length)&&(e=e.subarray?e.subarray(r,r+t):Array.prototype.slice.call(e,r,r+t)),r=!0,S(),!(t=void 0))throw new ce(48);p.set(e,t)}else r=!1,t=e.byteOffset;return{kb:t,bb:r}},Sa:(e,t,r,a)=>(te.wa.write(e,t,0,a,r,!1),0)}},re=(e,t)=>{var r=0;return e&&(r|=365),t&&(r|=146),r},ae=null,ne={},oe=[],se=1,ie=null,_e=!0,ce=null,fe={};function ue(e,t={}){if(!(e=O(e)))return{path:"",node:null};if(8<(t=Object.assign({Oa:!0,Ka:0},t)).Ka)throw new ce(32);e=e.split("/").filter((e=>!!e));for(var r=ae,a="/",n=0;n<e.length;n++){var o=n===e.length-1;if(o&&t.parent)break;if(r=ve(r,e[n]),a=$(a+"/"+e[n]),r.Ga&&(!o||o&&t.Oa)&&(r=r.Ga.root),!o||t.Na)for(o=0;40960==(61440&r.mode);)if(r=Se(a),r=ue(a=O(F(a),r),{Ka:t.Ka+1}).node,40<o++)throw new ce(32)}return{path:a,node:r}}function le(e){for(var t;;){if(e===e.parent)return e=e.Aa.Ra,t?"/"!==e[e.length-1]?`${e}/${t}`:e+t:e;t=t?`${e.name}/${t}`:e.name,e=e.parent}}function de(e,t){for(var r=0,a=0;a<t.length;a++)r=(r<<5)-r+t.charCodeAt(a)|0;return(e+r>>>0)%ie.length}function ve(e,t){var r;if(r=(r=ye(e,"x"))?r:e.ua.lookup?0:2)throw new ce(r,e);for(r=ie[de(e.id,t)];r;r=r.Za){var a=r.name;if(r.parent.id===e.id&&a===t)return r}return e.ua.lookup(e,t)}function he(e,t,r,a){return t=de((e=new je(e,t,r,a)).parent.id,e.name),e.Za=ie[t],ie[t]=e}function pe(e){var t=["r","w","rw"][3&e];return 512&e&&(t+="w"),t}function ye(e,t){return _e?0:!t.includes("r")||292&e.mode?t.includes("w")&&!(146&e.mode)||t.includes("x")&&!(73&e.mode)?2:0:2}function we(e,t){try{return ve(e,t),20}catch(e){}return ye(e,"wx")}function me(e){if(!(e=oe[e]))throw new ce(8);return e}function be(e,t=-1){return Me||((Me=function(){this.Ha={}}).prototype={},Object.defineProperties(Me.prototype,{object:{get(){return this.node},set(e){this.node=e}},flags:{get(){return this.Ha.flags},set(e){this.Ha.flags=e}},position:{get(){return this.Ha.position},set(e){this.Ha.position=e}}})),e=Object.assign(new Me,e),-1==t&&(t=function(){for(var e=0;4096>=e;e++)if(!oe[e])return e;throw new ce(33)}()),e.fd=t,oe[t]=e}var Ee,ge={open(e){e.wa=ne[e.node.rdev].wa,e.wa.open?.(e)},Ea(){throw new ce(70)}};function Pe(e,t){ne[e]={wa:t}}function Ae(e,t){var r="/"===t,a=!t;if(r&&ae)throw new ce(10);if(!r&&!a){var n=ue(t,{Oa:!1});if(t=n.path,(n=n.node).Ga)throw new ce(10);if(16384!=(61440&n.mode))throw new ce(54)}t={type:e,jb:{},Ra:t,Ya:[]},(e=e.Aa(t)).Aa=t,t.root=e,r?ae=e:n&&(n.Ga=t,n.Aa&&n.Aa.Ya.push(t))}function ke(e,t,r){var a=ue(e,{parent:!0}).node;if(!(e=K(e))||"."===e||".."===e)throw new ce(28);var n=we(a,e);if(n)throw new ce(n);if(!a.ua.Fa)throw new ce(63);return a.ua.Fa(a,e,t,r)}function Be(e){return ke(e,16895,0)}function Te(e,t,r){void 0===r&&(r=t,t=438),ke(e,8192|t,r)}function xe(e,t){if(!O(e))throw new ce(44);var r=ue(t,{parent:!0}).node;if(!r)throw new ce(44);var a=we(r,t=K(t));if(a)throw new ce(a);if(!r.ua.symlink)throw new ce(63);r.ua.symlink(r,t,e)}function Se(e){if(!(e=ue(e).node))throw new ce(44);if(!e.ua.readlink)throw new ce(28);return O(le(e.parent),e.ua.readlink(e))}function Le(e,t,r){if(""===e)throw new ce(44);if("string"==typeof t){var n={r:0,"r+":2,w:577,"w+":578,a:1089,"a+":1090}[t];if(void 0===n)throw Error(`Unknown file open mode: ${t}`);t=n}if(r=64&t?4095&(void 0===r?438:r)|32768:0,"object"==typeof e)var o=e;else{e=$(e);try{o=ue(e,{Na:!(131072&t)}).node}catch(e){}}if(n=!1,64&t)if(o){if(128&t)throw new ce(20)}else o=ke(e,r,0),n=!0;if(!o)throw new ce(44);if(8192==(61440&o.mode)&&(t&=-513),65536&t&&16384!=(61440&o.mode))throw new ce(54);if(!n&&(r=o?40960==(61440&o.mode)?32:16384==(61440&o.mode)&&("r"!==pe(t)||512&t)?31:ye(o,pe(t)):44))throw new ce(r);if(512&t&&!n){if(!(r="string"==typeof(r=o)?ue(r,{Na:!0}).node:r).ua.za)throw new ce(63);if(16384==(61440&r.mode))throw new ce(31);if(32768!=(61440&r.mode))throw new ce(28);if(n=ye(r,"w"))throw new ce(n);r.ua.za(r,{size:0,timestamp:Date.now()})}return t&=-131713,(o=be({node:o,path:le(o),flags:t,seekable:!0,position:0,wa:o.wa,ab:[],error:!1})).wa.open&&o.wa.open(o),!a.logReadFiles||1&t||(Ue||={},e in Ue||(Ue[e]=1)),o}function Re(e,t,r){if(null===e.fd)throw new ce(8);if(!e.seekable||!e.wa.Ea)throw new ce(70);if(0!=r&&1!=r&&2!=r)throw new ce(28);e.position=e.wa.Ea(e,t,r),e.ab=[]}function ze(){ce||(ce=function(e,t){this.name="ErrnoError",this.node=t,this.$a=function(e){this.Da=e},this.$a(e),this.message="FS error"},ce.prototype=Error(),ce.prototype.constructor=ce,[44].forEach((e=>{fe[e]=new ce(e),fe[e].stack="<generic error, no stack>"})))}function He(e,t,r){e=$("/dev/"+e);var a=re(!!t,!!r);Ne||=64;var n=Ne++<<8|0;Pe(n,{open(e){e.seekable=!1},close(){r?.buffer?.length&&r(10)},read(e,r,a,n){for(var o=0,s=0;s<n;s++){try{var i=t()}catch(e){throw new ce(29)}if(void 0===i&&0===o)throw new ce(6);if(null==i)break;o++,r[a+s]=i}return o&&(e.node.timestamp=Date.now()),o},write(e,t,a,n){for(var o=0;o<n;o++)try{r(t[a+o])}catch(e){throw new ce(29)}return n&&(e.node.timestamp=Date.now()),o}}),Te(e,a,n)}var Ne,Me,Ue,Ce={},De=void 0;function Ye(){var e=m[+De>>2];return De+=4,e}var Ie,$e={},Fe=0,Ke=e=>{h=e,Y||0<Fe||(a.onExit?.(e),E=!0),_(e,new U(e))};function je(e,t,r,a){e||=this,this.parent=e,this.Aa=e.Aa,this.Ga=null,this.id=se++,this.name=t,this.mode=r,this.ua={},this.wa={},this.rdev=a}Ie=()=>performance.now(),Object.defineProperties(je.prototype,{read:{get:function(){return 365==(365&this.mode)},set:function(e){e?this.mode|=365:this.mode&=-366}},write:{get:function(){return 146==(146&this.mode)},set:function(e){e?this.mode|=146:this.mode&=-147}}}),ze(),ie=Array(4096),Ae(te,"/"),Be("/tmp"),Be("/home"),Be("/home/web_user"),function(){Be("/dev"),Pe(259,{read:()=>0,write:(e,t,r,a)=>a}),Te("/dev/null",259),J(1280,X),J(1536,Z),Te("/dev/tty",1280),Te("/dev/tty1",1536);var e=new Uint8Array(1024),t=0,r=()=>(0===t&&(t=j(e).byteLength),e[--t]);He("random",r),He("urandom",r),Be("/dev/shm"),Be("/dev/shm/tmp")}(),function(){Be("/proc");var e=Be("/proc/self");Be("/proc/self/fd"),Ae({Aa(){var t=he(e,"fd",16895,73);return t.ua={lookup(e,t){var r=me(+t);return(e={parent:null,Aa:{Ra:"fake"},ua:{readlink:()=>r.path}}).parent=e}},t}},"/proc/self/fd")}();var Oe={z:(e,t)=>C.get(e)(t),r:function(e,t,r){De=r;try{var a=me(e);switch(t){case 0:var n=Ye();if(0>n)return-28;for(;oe[n];)n++;return be(a,n).fd;case 1:case 2:case 6:case 7:return 0;case 3:return a.flags;case 4:return n=Ye(),a.flags|=n,0;case 5:return n=Ye(),w[n+0>>1]=2,0;case 16:case 8:default:return-28;case 9:return m[Ve()>>2]=28,-1}}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return-e.Da}},y:function(e,t,r){De=r;try{var a=me(e);switch(t){case 21509:case 21510:case 21511:case 21512:case 21524:case 21515:return a.tty?0:-59;case 21505:if(!a.tty)return-59;if(a.tty.Ba.Va){t=[3,28,127,21,4,0,1,0,17,19,26,0,18,15,23,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];var n=Ye();m[n>>2]=25856,m[n+4>>2]=5,m[n+8>>2]=191,m[n+12>>2]=35387;for(var o=0;32>o;o++)p[n+o+17>>0]=t[o]||0}return 0;case 21506:case 21507:case 21508:if(!a.tty)return-59;if(a.tty.Ba.Wa)for(n=Ye(),t=[],o=0;32>o;o++)t.push(p[n+o+17>>0]);return 0;case 21519:return a.tty?(n=Ye(),m[n>>2]=0):-59;case 21520:return a.tty?-28:-59;case 21531:if(n=Ye(),!a.wa.Ua)throw new ce(59);return a.wa.Ua(a,t,n);case 21523:return a.tty?(a.tty.Ba.Xa&&(o=[24,80],n=Ye(),w[n>>1]=o[0],w[n+2>>1]=o[1]),0):-59;default:return-28}}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return-e.Da}},o:function(e,t,r,a){De=a;try{var n=t=t?V(y,t):"";if("/"===n.charAt(0))t=n;else{var o=-100===e?"/":me(e).path;if(0==n.length)throw new ce(44);t=$(o+"/"+n)}return Le(t,r,a?Ye():0).fd}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return-e.Da}},B:()=>{Y=!1,Fe=0},v:()=>{throw 1/0},C:(e,t)=>{if($e[e]&&(clearTimeout($e[e].id),delete $e[e]),!t)return 0;var r=setTimeout((()=>{delete $e[e],(e=>{if(!E)try{if(e(),!(Y||0<Fe))try{h=e=h,Ke(e)}catch(e){e instanceof U||"unwind"==e||_(1,e)}}catch(e){e instanceof U||"unwind"==e||_(1,e)}})((()=>qe(e,Ie())))}),t);return $e[e]={id:r,lb:t},0},p:()=>{S("")},D:()=>Date.now(),E:(e,t,r)=>y.copyWithin(e,t,t+r),w:e=>{var t=y.length;if(2147483648<(e>>>=0))return!1;for(var r=1;4>=r;r*=2){var a=t*(1+.2/r);a=Math.min(a,e+100663296);var n=Math;a=Math.max(e,a);e:{n=(n.min.call(n,2147483648,a+(65536-a%65536)%65536)-v.buffer.byteLength+65535)/65536;try{v.grow(n),g();var o=1;break e}catch(e){}o=void 0}if(o)return!0}return!1},h:e=>{h=e,Ke(e)},n:function(e){try{var t=me(e);if(null===t.fd)throw new ce(8);t.Ia&&(t.Ia=null);try{t.wa.close&&t.wa.close(t)}catch(e){throw e}finally{oe[t.fd]=null}return t.fd=null,0}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return e.Da}},t:function(e,t,r,a){try{e:{var n=me(e);e=t;for(var o,s=t=0;s<r;s++){var i=b[e>>2],_=b[e+4>>2];e+=8;var c=n,f=i,u=_,l=o,d=p;if(0>u||0>l)throw new ce(28);if(null===c.fd)throw new ce(8);if(1==(2097155&c.flags))throw new ce(8);if(16384==(61440&c.node.mode))throw new ce(31);if(!c.wa.read)throw new ce(28);var v=void 0!==l;if(v){if(!c.seekable)throw new ce(70)}else l=c.position;var h=c.wa.read(c,d,f,u,l);v||(c.position+=h);var y=h;if(0>y){var w=-1;break e}if(t+=y,y<_)break;void 0!==o&&(o+=y)}w=t}return b[a>>2]=w,0}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return e.Da}},x:function(e,t,r,a,n){t=r+2097152>>>0<4194305-!!t?(t>>>0)+4294967296*r:NaN;try{if(isNaN(t))return 61;var o=me(e);return Re(o,t,a),z=[o.position>>>0,(R=o.position,1<=+Math.abs(R)?0<R?+Math.floor(R/4294967296)>>>0:~~+Math.ceil((R-+(~~R>>>0))/4294967296)>>>0:0)],m[n>>2]=z[0],m[n+4>>2]=z[1],o.Ia&&0===t&&0===a&&(o.Ia=null),0}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return e.Da}},u:function(e,t,r,a){try{e:{var n=me(e);e=t;for(var o,s=t=0;s<r;s++){var i=b[e>>2],_=b[e+4>>2];e+=8;var c=n,f=i,u=_,l=o,d=p;if(0>u||0>l)throw new ce(28);if(null===c.fd)throw new ce(8);if(0==(2097155&c.flags))throw new ce(8);if(16384==(61440&c.node.mode))throw new ce(31);if(!c.wa.write)throw new ce(28);c.seekable&&1024&c.flags&&Re(c,0,2);var v=void 0!==l;if(v){if(!c.seekable)throw new ce(70)}else l=c.position;var h=c.wa.write(c,d,f,u,l,void 0);v||(c.position+=h);var y=h;if(0>y){var w=-1;break e}t+=y,void 0!==o&&(o+=y)}w=t}return b[a>>2]=w,0}catch(e){if(void 0===Ce||"ErrnoError"!==e.name)throw e;return e.Da}},d:function(e){var t=Qe();try{return C.get(e)()}catch(e){if(Xe(t),e!==e+0)throw e;Je(1,0)}},f:function(e,t){var r=Qe();try{return C.get(e)(t)}catch(e){if(Xe(r),e!==e+0)throw e;Je(1,0)}},e:function(e,t,r){var a=Qe();try{return C.get(e)(t,r)}catch(e){if(Xe(a),e!==e+0)throw e;Je(1,0)}},j:function(e,t,r,a){var n=Qe();try{return C.get(e)(t,r,a)}catch(e){if(Xe(n),e!==e+0)throw e;Je(1,0)}},s:function(e,t,r,a,n){var o=Qe();try{return C.get(e)(t,r,a,n)}catch(e){if(Xe(o),e!==e+0)throw e;Je(1,0)}},i:function(e){var t=Qe();try{C.get(e)()}catch(e){if(Xe(t),e!==e+0)throw e;Je(1,0)}},b:function(e,t){var r=Qe();try{C.get(e)(t)}catch(e){if(Xe(r),e!==e+0)throw e;Je(1,0)}},a:function(e,t,r){var a=Qe();try{C.get(e)(t,r)}catch(e){if(Xe(a),e!==e+0)throw e;Je(1,0)}},c:function(e,t,r,a){var n=Qe();try{C.get(e)(t,r,a)}catch(e){if(Xe(n),e!==e+0)throw e;Je(1,0)}},g:function(e,t,r,a,n){var o=Qe();try{C.get(e)(t,r,a,n)}catch(e){if(Xe(o),e!==e+0)throw e;Je(1,0)}},k:function(e,t,r,a,n,o){var s=Qe();try{C.get(e)(t,r,a,n,o)}catch(e){if(Xe(s),e!==e+0)throw e;Je(1,0)}},l:function(e,t,r,a,n,o,s){var i=Qe();try{C.get(e)(t,r,a,n,o,s)}catch(e){if(Xe(i),e!==e+0)throw e;Je(1,0)}},m:function(e,t,r,a,n,o,s,i){var _=Qe();try{C.get(e)(t,r,a,n,o,s,i)}catch(e){if(Xe(_),e!==e+0)throw e;Je(1,0)}},q:function(e,t,r,a,n,o,s,i,_){var c=Qe();try{C.get(e)(t,r,a,n,o,s,i,_)}catch(e){if(Xe(c),e!==e+0)throw e;Je(1,0)}},A:Ke},We=function(){function e(e){return We=e.exports,v=We.F,g(),C=We.ta,A.unshift(We.G),T--,a.monitorRunDependencies?.(T),0==T&&x&&(e=x,x=null,e()),We}var t={a:Oe};if(T++,a.monitorRunDependencies?.(T),a.instantiateWasm)try{return a.instantiateWasm(t,e)}catch(e){d(`Module.instantiateWasm callback failed with error: ${e}`),r(e)}return function(e,t){return M(e,t)}(t,(function(t){e(t.instance)})).catch(r),{}}();a._vscp_error_ctx_size=()=>(a._vscp_error_ctx_size=We.H)(),a._vscp_error_reset=e=>(a._vscp_error_reset=We.I)(e),a._vscp_error_status=e=>(a._vscp_error_status=We.J)(e),a._vscp_pythia_configure=()=>(a._vscp_pythia_configure=We.K)(),a._vscp_pythia_cleanup=()=>(a._vscp_pythia_cleanup=We.L)(),a._vscp_pythia_blinded_password_buf_len=()=>(a._vscp_pythia_blinded_password_buf_len=We.M)(),a._vscp_pythia_deblinded_password_buf_len=()=>(a._vscp_pythia_deblinded_password_buf_len=We.N)(),a._vscp_pythia_blinding_secret_buf_len=()=>(a._vscp_pythia_blinding_secret_buf_len=We.O)(),a._vscp_pythia_transformation_private_key_buf_len=()=>(a._vscp_pythia_transformation_private_key_buf_len=We.P)(),a._vscp_pythia_transformation_public_key_buf_len=()=>(a._vscp_pythia_transformation_public_key_buf_len=We.Q)(),a._vscp_pythia_transformed_password_buf_len=()=>(a._vscp_pythia_transformed_password_buf_len=We.R)(),a._vscp_pythia_transformed_tweak_buf_len=()=>(a._vscp_pythia_transformed_tweak_buf_len=We.S)(),a._vscp_pythia_proof_value_buf_len=()=>(a._vscp_pythia_proof_value_buf_len=We.T)(),a._vscp_pythia_password_update_token_buf_len=()=>(a._vscp_pythia_password_update_token_buf_len=We.U)(),a._vscp_pythia_blind=(e,t,r)=>(a._vscp_pythia_blind=We.V)(e,t,r),a._vscp_pythia_deblind=(e,t,r)=>(a._vscp_pythia_deblind=We.W)(e,t,r),a._vscp_pythia_compute_transformation_key_pair=(e,t,r,n,o)=>(a._vscp_pythia_compute_transformation_key_pair=We.X)(e,t,r,n,o),a._vscp_pythia_transform=(e,t,r,n,o)=>(a._vscp_pythia_transform=We.Y)(e,t,r,n,o),a._vscp_pythia_prove=(e,t,r,n,o,s,i)=>(a._vscp_pythia_prove=We.Z)(e,t,r,n,o,s,i),a._vscp_pythia_verify=(e,t,r,n,o,s,i)=>(a._vscp_pythia_verify=We._)(e,t,r,n,o,s,i),a._vscp_pythia_get_password_update_token=(e,t,r)=>(a._vscp_pythia_get_password_update_token=We.$)(e,t,r),a._vscp_pythia_update_deblinded_with_token=(e,t,r)=>(a._vscp_pythia_update_deblinded_with_token=We.aa)(e,t,r),a._vsc_buffer_new=()=>(a._vsc_buffer_new=We.ba)(),a._vsc_buffer_new_with_capacity=e=>(a._vsc_buffer_new_with_capacity=We.ca)(e),a._vsc_buffer_delete=e=>(a._vsc_buffer_delete=We.da)(e),a._vsc_buffer_data=(e,t)=>(a._vsc_buffer_data=We.ea)(e,t),a._vsc_buffer_make_secure=e=>(a._vsc_buffer_make_secure=We.fa)(e),a._vsc_buffer_bytes=e=>(a._vsc_buffer_bytes=We.ga)(e),a._vsc_buffer_len=e=>(a._vsc_buffer_len=We.ha)(e),a._vsc_data_ctx_size=()=>(a._vsc_data_ctx_size=We.ia)(),a._vsc_data=(e,t,r)=>(a._vsc_data=We.ja)(e,t,r),a._vsc_data_len=e=>(a._vsc_data_len=We.ka)(e),a._vsc_data_bytes=e=>(a._vsc_data_bytes=We.la)(e);var Ve=()=>(Ve=We.ma)(),qe=(e,t)=>(qe=We.na)(e,t);a._malloc=e=>(a._malloc=We.oa)(e),a._free=e=>(a._free=We.pa)(e);var Ge,Je=(e,t)=>(Je=We.qa)(e,t),Qe=()=>(Qe=We.ra)(),Xe=e=>(Xe=We.sa)(e);function Ze(){function e(){if(!Ge&&(Ge=!0,a.calledRun=!0,!E)){if(a.noFSInit||Ee||(Ee=!0,ze(),a.stdin=a.stdin,a.stdout=a.stdout,a.stderr=a.stderr,a.stdin?He("stdin",a.stdin):xe("/dev/tty","/dev/stdin"),a.stdout?He("stdout",null,a.stdout):xe("/dev/tty","/dev/stdout"),a.stderr?He("stderr",null,a.stderr):xe("/dev/tty1","/dev/stderr"),Le("/dev/stdin",0),Le("/dev/stdout",1),Le("/dev/stderr",1)),_e=!1,D(A),t(a),a.onRuntimeInitialized&&a.onRuntimeInitialized(),a.postRun)for("function"==typeof a.postRun&&(a.postRun=[a.postRun]);a.postRun.length;){var e=a.postRun.shift();k.unshift(e)}D(k)}}if(!(0<T)){if(a.preRun)for("function"==typeof a.preRun&&(a.preRun=[a.preRun]);a.preRun.length;)B();D(P),0<T||(a.setStatus?(a.setStatus("Running..."),setTimeout((function(){setTimeout((function(){a.setStatus("")}),1),e()}),1)):e())}}if(x=function e(){Ge||Ze(),Ge||(x=e)},a.preInit)for("function"==typeof a.preInit&&(a.preInit=[a.preInit]);0<a.preInit.length;)a.preInit.pop()();return Ze(),e.ready});e.exports=a}(t);var r=t.exports;var a=(e,t)=>{class r extends Error{constructor(e){super(e),this.name="PythiaError",this.message=e}static handleStatusCode(e){if(0!=e){if(-1==e)throw new r("This error should not be returned if assertions is enabled.");if(-200==e)throw new r("Underlying pythia library returns -1.");if(-202==e)throw new r("Underlying random number generator failed.");throw new r("Unexpected status code:"+e)}}}return r},n={};function o(e,t){if(!("number"==typeof t||t instanceof Number))throw new TypeError(`'${e}' is not a number`);if(Number.isNaN(t))throw new TypeError(`'${e}' is NaN`);if(t===1/0)throw new TypeError(`'${e}' is Infinity`);if(t===-1/0)throw new TypeError(`'${e}' is -Infinity`)}function s(e,t){if(o(e,t),0==t)throw new TypeError(`'${e}' is NULL`)}n.ensureNumber=o,n.ensureString=function(e,t){if(!("string"==typeof t||t instanceof String))throw new TypeError(`'${e}' is not a string`)},n.ensureBoolean=function(e,t){if("boolean"!=typeof t)throw new TypeError(`'${e}' is not a boolean`)},n.ensureByteArray=function(e,t){if(!(t instanceof Uint8Array))throw new TypeError(`'${e}' is not an Uint8Array`)},n.ensureClass=function(e,t,r){if(!(t instanceof r))throw new TypeError(`'${e}' is not an instance of the class ${r.name}`);s(e,t.ctxPtr)},n.ensureNotNull=s,n.ensureImplementInterface=function(e,t,r,a,n){if(s(e,t.ctxPtr),!n.isImplemented(t.ctxPtr,a))throw new TypeError(`'${e}' does not implement interface '${r}'`)};const i=n;const _=r,c=a,f=(e,t)=>class{static configure(){const r=e._vscp_pythia_configure();t.PythiaError.handleStatusCode(r)}static cleanup(){e._vscp_pythia_cleanup()}static blindedPasswordBufLen(){let t;return t=e._vscp_pythia_blinded_password_buf_len(),t}static deblindedPasswordBufLen(){let t;return t=e._vscp_pythia_deblinded_password_buf_len(),t}static blindingSecretBufLen(){let t;return t=e._vscp_pythia_blinding_secret_buf_len(),t}static transformationPrivateKeyBufLen(){let t;return t=e._vscp_pythia_transformation_private_key_buf_len(),t}static transformationPublicKeyBufLen(){let t;return t=e._vscp_pythia_transformation_public_key_buf_len(),t}static transformedPasswordBufLen(){let t;return t=e._vscp_pythia_transformed_password_buf_len(),t}static transformedTweakBufLen(){let t;return t=e._vscp_pythia_transformed_tweak_buf_len(),t}static proofValueBufLen(){let t;return t=e._vscp_pythia_proof_value_buf_len(),t}static passwordUpdateTokenBufLen(){let t;return t=e._vscp_pythia_password_update_token_buf_len(),t}static blind(r){i.ensureByteArray("password",r);const a=r.length*r.BYTES_PER_ELEMENT,n=e._malloc(a);e.HEAP8.set(r,n);const o=e._vsc_data_ctx_size(),s=e._malloc(o);e._vsc_data(s,n,a);const _=t.Pythia.blindedPasswordBufLen(),c=e._vsc_buffer_new_with_capacity(_),f=t.Pythia.blindingSecretBufLen(),u=e._vsc_buffer_new_with_capacity(f);try{const r=e._vscp_pythia_blind(s,c,u);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(c),n=e._vsc_buffer_len(c),o=e.HEAPU8.slice(a,a+n),i=e._vsc_buffer_bytes(u),_=e._vsc_buffer_len(u);return{blindedPassword:o,blindingSecret:e.HEAPU8.slice(i,i+_)}}finally{e._free(n),e._free(s),e._vsc_buffer_delete(c),e._vsc_buffer_delete(u)}}static deblind(r,a){i.ensureByteArray("transformedPassword",r),i.ensureByteArray("blindingSecret",a);const n=r.length*r.BYTES_PER_ELEMENT,o=e._malloc(n);e.HEAP8.set(r,o);const s=e._vsc_data_ctx_size(),_=e._malloc(s);e._vsc_data(_,o,n);const c=a.length*a.BYTES_PER_ELEMENT,f=e._malloc(c);e.HEAP8.set(a,f);const u=e._vsc_data_ctx_size(),l=e._malloc(u);e._vsc_data(l,f,c);const d=t.Pythia.deblindedPasswordBufLen(),v=e._vsc_buffer_new_with_capacity(d);try{const r=e._vscp_pythia_deblind(_,l,v);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(v),n=e._vsc_buffer_len(v);return e.HEAPU8.slice(a,a+n)}finally{e._free(o),e._free(_),e._free(f),e._free(l),e._vsc_buffer_delete(v)}}static computeTransformationKeyPair(r,a,n){i.ensureByteArray("transformationKeyId",r),i.ensureByteArray("pythiaSecret",a),i.ensureByteArray("pythiaScopeSecret",n);const o=r.length*r.BYTES_PER_ELEMENT,s=e._malloc(o);e.HEAP8.set(r,s);const _=e._vsc_data_ctx_size(),c=e._malloc(_);e._vsc_data(c,s,o);const f=a.length*a.BYTES_PER_ELEMENT,u=e._malloc(f);e.HEAP8.set(a,u);const l=e._vsc_data_ctx_size(),d=e._malloc(l);e._vsc_data(d,u,f);const v=n.length*n.BYTES_PER_ELEMENT,h=e._malloc(v);e.HEAP8.set(n,h);const p=e._vsc_data_ctx_size(),y=e._malloc(p);e._vsc_data(y,h,v);const w=t.Pythia.transformationPrivateKeyBufLen(),m=e._vsc_buffer_new_with_capacity(w),b=t.Pythia.transformationPublicKeyBufLen(),E=e._vsc_buffer_new_with_capacity(b);try{const r=e._vscp_pythia_compute_transformation_key_pair(c,d,y,m,E);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(m),n=e._vsc_buffer_len(m),o=e.HEAPU8.slice(a,a+n),s=e._vsc_buffer_bytes(E),i=e._vsc_buffer_len(E);return{transformationPrivateKey:o,transformationPublicKey:e.HEAPU8.slice(s,s+i)}}finally{e._free(s),e._free(c),e._free(u),e._free(d),e._free(h),e._free(y),e._vsc_buffer_delete(m),e._vsc_buffer_delete(E)}}static transform(r,a,n){i.ensureByteArray("blindedPassword",r),i.ensureByteArray("tweak",a),i.ensureByteArray("transformationPrivateKey",n);const o=r.length*r.BYTES_PER_ELEMENT,s=e._malloc(o);e.HEAP8.set(r,s);const _=e._vsc_data_ctx_size(),c=e._malloc(_);e._vsc_data(c,s,o);const f=a.length*a.BYTES_PER_ELEMENT,u=e._malloc(f);e.HEAP8.set(a,u);const l=e._vsc_data_ctx_size(),d=e._malloc(l);e._vsc_data(d,u,f);const v=n.length*n.BYTES_PER_ELEMENT,h=e._malloc(v);e.HEAP8.set(n,h);const p=e._vsc_data_ctx_size(),y=e._malloc(p);e._vsc_data(y,h,v);const w=t.Pythia.transformedPasswordBufLen(),m=e._vsc_buffer_new_with_capacity(w),b=t.Pythia.transformedTweakBufLen(),E=e._vsc_buffer_new_with_capacity(b);try{const r=e._vscp_pythia_transform(c,d,y,m,E);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(m),n=e._vsc_buffer_len(m),o=e.HEAPU8.slice(a,a+n),s=e._vsc_buffer_bytes(E),i=e._vsc_buffer_len(E);return{transformedPassword:o,transformedTweak:e.HEAPU8.slice(s,s+i)}}finally{e._free(s),e._free(c),e._free(u),e._free(d),e._free(h),e._free(y),e._vsc_buffer_delete(m),e._vsc_buffer_delete(E)}}static prove(r,a,n,o,s){i.ensureByteArray("transformedPassword",r),i.ensureByteArray("blindedPassword",a),i.ensureByteArray("transformedTweak",n),i.ensureByteArray("transformationPrivateKey",o),i.ensureByteArray("transformationPublicKey",s);const _=r.length*r.BYTES_PER_ELEMENT,c=e._malloc(_);e.HEAP8.set(r,c);const f=e._vsc_data_ctx_size(),u=e._malloc(f);e._vsc_data(u,c,_);const l=a.length*a.BYTES_PER_ELEMENT,d=e._malloc(l);e.HEAP8.set(a,d);const v=e._vsc_data_ctx_size(),h=e._malloc(v);e._vsc_data(h,d,l);const p=n.length*n.BYTES_PER_ELEMENT,y=e._malloc(p);e.HEAP8.set(n,y);const w=e._vsc_data_ctx_size(),m=e._malloc(w);e._vsc_data(m,y,p);const b=o.length*o.BYTES_PER_ELEMENT,E=e._malloc(b);e.HEAP8.set(o,E);const g=e._vsc_data_ctx_size(),P=e._malloc(g);e._vsc_data(P,E,b);const A=s.length*s.BYTES_PER_ELEMENT,k=e._malloc(A);e.HEAP8.set(s,k);const B=e._vsc_data_ctx_size(),T=e._malloc(B);e._vsc_data(T,k,A);const x=t.Pythia.proofValueBufLen(),S=e._vsc_buffer_new_with_capacity(x),L=t.Pythia.proofValueBufLen(),R=e._vsc_buffer_new_with_capacity(L);try{const r=e._vscp_pythia_prove(u,h,m,P,T,S,R);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(S),n=e._vsc_buffer_len(S),o=e.HEAPU8.slice(a,a+n),s=e._vsc_buffer_bytes(R),i=e._vsc_buffer_len(R);return{proofValueC:o,proofValueU:e.HEAPU8.slice(s,s+i)}}finally{e._free(c),e._free(u),e._free(d),e._free(h),e._free(y),e._free(m),e._free(E),e._free(P),e._free(k),e._free(T),e._vsc_buffer_delete(S),e._vsc_buffer_delete(R)}}static verify(r,a,n,o,s,_){i.ensureByteArray("transformedPassword",r),i.ensureByteArray("blindedPassword",a),i.ensureByteArray("tweak",n),i.ensureByteArray("transformationPublicKey",o),i.ensureByteArray("proofValueC",s),i.ensureByteArray("proofValueU",_);const c=r.length*r.BYTES_PER_ELEMENT,f=e._malloc(c);e.HEAP8.set(r,f);const u=e._vsc_data_ctx_size(),l=e._malloc(u);e._vsc_data(l,f,c);const d=a.length*a.BYTES_PER_ELEMENT,v=e._malloc(d);e.HEAP8.set(a,v);const h=e._vsc_data_ctx_size(),p=e._malloc(h);e._vsc_data(p,v,d);const y=n.length*n.BYTES_PER_ELEMENT,w=e._malloc(y);e.HEAP8.set(n,w);const m=e._vsc_data_ctx_size(),b=e._malloc(m);e._vsc_data(b,w,y);const E=o.length*o.BYTES_PER_ELEMENT,g=e._malloc(E);e.HEAP8.set(o,g);const P=e._vsc_data_ctx_size(),A=e._malloc(P);e._vsc_data(A,g,E);const k=s.length*s.BYTES_PER_ELEMENT,B=e._malloc(k);e.HEAP8.set(s,B);const T=e._vsc_data_ctx_size(),x=e._malloc(T);e._vsc_data(x,B,k);const S=_.length*_.BYTES_PER_ELEMENT,L=e._malloc(S);e.HEAP8.set(_,L);const R=e._vsc_data_ctx_size(),z=e._malloc(R);e._vsc_data(z,L,S);const H=e._vscp_error_ctx_size(),N=e._malloc(H);let M;e._vscp_error_reset(N);try{M=e._vscp_pythia_verify(l,p,b,A,x,z,N);const r=e._vscp_error_status(N);t.PythiaError.handleStatusCode(r);return!!M}finally{e._free(f),e._free(l),e._free(v),e._free(p),e._free(w),e._free(b),e._free(g),e._free(A),e._free(B),e._free(x),e._free(L),e._free(z),e._free(N)}}static getPasswordUpdateToken(r,a){i.ensureByteArray("previousTransformationPrivateKey",r),i.ensureByteArray("newTransformationPrivateKey",a);const n=r.length*r.BYTES_PER_ELEMENT,o=e._malloc(n);e.HEAP8.set(r,o);const s=e._vsc_data_ctx_size(),_=e._malloc(s);e._vsc_data(_,o,n);const c=a.length*a.BYTES_PER_ELEMENT,f=e._malloc(c);e.HEAP8.set(a,f);const u=e._vsc_data_ctx_size(),l=e._malloc(u);e._vsc_data(l,f,c);const d=t.Pythia.passwordUpdateTokenBufLen(),v=e._vsc_buffer_new_with_capacity(d);try{const r=e._vscp_pythia_get_password_update_token(_,l,v);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(v),n=e._vsc_buffer_len(v);return e.HEAPU8.slice(a,a+n)}finally{e._free(o),e._free(_),e._free(f),e._free(l),e._vsc_buffer_delete(v)}}static updateDeblindedWithToken(r,a){i.ensureByteArray("deblindedPassword",r),i.ensureByteArray("passwordUpdateToken",a);const n=r.length*r.BYTES_PER_ELEMENT,o=e._malloc(n);e.HEAP8.set(r,o);const s=e._vsc_data_ctx_size(),_=e._malloc(s);e._vsc_data(_,o,n);const c=a.length*a.BYTES_PER_ELEMENT,f=e._malloc(c);e.HEAP8.set(a,f);const u=e._vsc_data_ctx_size(),l=e._malloc(u);e._vsc_data(l,f,c);const d=t.Pythia.deblindedPasswordBufLen(),v=e._vsc_buffer_new_with_capacity(d);try{const r=e._vscp_pythia_update_deblinded_with_token(_,l,v);t.PythiaError.handleStatusCode(r);const a=e._vsc_buffer_bytes(v),n=e._vsc_buffer_len(v);return e.HEAPU8.slice(a,a+n)}finally{e._free(o),e._free(_),e._free(f),e._free(l),e._vsc_buffer_delete(v)}}};var u=e((e=>new Promise(((t,r)=>{_(e).then((e=>{const r={};r.PythiaError=c(),r.Pythia=f(e,r),t(r)})).catch((e=>{r(e)}))}))));module.exports=u;
