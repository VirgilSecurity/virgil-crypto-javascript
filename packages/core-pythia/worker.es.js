var e=function(e,t){return e(t={exports:{}},t.exports),t.exports}((function(e,t){var n,r=(n="undefined"!=typeof document&&document.currentScript?document.currentScript.src:void 0,function(e){var t;e=e||{},t||(t=void 0!==e?e:{});var r,a={};for(r in t)t.hasOwnProperty(r)&&(a[r]=t[r]);function o(e,t){throw t}var i,s="";s=self.location.href,n&&(s=n),s=0!==s.indexOf("blob:")?s.substr(0,s.lastIndexOf("/")+1):"",i=function(e){var t=new XMLHttpRequest;return t.open("GET",e,!1),t.responseType="arraybuffer",t.send(null),new Uint8Array(t.response)};var c=t.print||console.log.bind(console),u=t.printErr||console.warn.bind(console);for(r in a)a.hasOwnProperty(r)&&(t[r]=a[r]);a=null,t.quit&&(o=t.quit);var f,l,_=0;t.wasmBinary&&(f=t.wasmBinary),t.noExitRuntime&&(l=t.noExitRuntime),"object"!=typeof WebAssembly&&u("no native wasm support detected");var d,p,y,h,v,m,w=new WebAssembly.Table({initial:321,maximum:321,element:"anyfunc"}),b=!1,E="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;function g(e,t,n){var r=t+n;for(n=t;e[n]&&!(n>=r);)++n;if(16<n-t&&e.subarray&&E)return E.decode(e.subarray(t,n));for(r="";t<n;){var a=e[t++];if(128&a){var o=63&e[t++];if(192==(224&a))r+=String.fromCharCode((31&a)<<6|o);else{var i=63&e[t++];65536>(a=224==(240&a)?(15&a)<<12|o<<6|i:(7&a)<<18|o<<12|i<<6|63&e[t++])?r+=String.fromCharCode(a):(a-=65536,r+=String.fromCharCode(55296|a>>10,56320|1023&a))}}else r+=String.fromCharCode(a)}return r}function P(e){return 0<e%65536&&(e+=65536-e%65536),e}function A(e){p=e,t.HEAP8=y=new Int8Array(e),t.HEAP16=v=new Int16Array(e),t.HEAP32=m=new Int32Array(e),t.HEAPU8=h=new Uint8Array(e),t.HEAPU16=new Uint16Array(e),t.HEAPU32=new Uint32Array(e),t.HEAPF32=new Float32Array(e),t.HEAPF64=new Float64Array(e)}"undefined"!=typeof TextDecoder&&new TextDecoder("utf-16le");var T=t.TOTAL_MEMORY||16777216;function L(e){for(;0<e.length;){var n=e.shift();if("function"==typeof n)n();else{var r=n.wb;"number"==typeof r?void 0===n.eb?t.dynCall_v(r):t.dynCall_vi(r,n.eb):r(void 0===n.eb?null:n.eb)}}}(d=t.wasmMemory?t.wasmMemory:new WebAssembly.Memory({initial:T/65536}))&&(p=d.buffer),T=p.byteLength,A(p),m[16580]=5309360;var B=[],x=[],M=[],S=[];function k(){var e=t.preRun.shift();B.unshift(e)}var R=Math.abs,N=Math.ceil,K=Math.floor,U=Math.min,H=0,C=null;function z(e){throw t.onAbort&&t.onAbort(e),c(e),u(e),b=!0,new WebAssembly.RuntimeError("abort("+e+"). Build with -s ASSERTIONS=1 for more info.")}function O(){var e=j;return String.prototype.startsWith?e.startsWith("data:application/octet-stream;base64,"):0===e.indexOf("data:application/octet-stream;base64,")}t.preloadedImages={},t.preloadedAudios={};var Y,I,j="libpythia.worker.wasm";if(!O()){var D=j;j=t.locateFile?t.locateFile(D,s):s+D}function W(){try{if(f)return new Uint8Array(f);if(i)return i(j);throw"both async and sync fetching of the wasm failed"}catch(e){z(e)}}function F(e,t){for(var n=0,r=e.length-1;0<=r;r--){var a=e[r];"."===a?e.splice(r,1):".."===a?(e.splice(r,1),n++):n&&(e.splice(r,1),n--)}if(t)for(;n;n--)e.unshift("..");return e}function V(e){var t="/"===e.charAt(0),n="/"===e.substr(-1);return(e=F(e.split("/").filter((function(e){return!!e})),!t).join("/"))||t||(e="."),e&&n&&(e+="/"),(t?"/":"")+e}function $(e){var t=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(e).slice(1);return e=t[0],t=t[1],e||t?(t&&(t=t.substr(0,t.length-1)),e+t):"."}function Q(e){if("/"===e)return"/";var t=e.lastIndexOf("/");return-1===t?e:e.substr(t+1)}function X(){for(var e="",t=!1,n=arguments.length-1;-1<=n&&!t;n--){if("string"!=typeof(t=0<=n?arguments[n]:"/"))throw new TypeError("Arguments to path.resolve must be strings");if(!t)return"";e=t+"/"+e,t="/"===t.charAt(0)}return(t?"/":"")+(e=F(e.split("/").filter((function(e){return!!e})),!t).join("/"))||"."}x.push({wb:function(){Ve()}});var q=[];function Z(e,t){q[e]={input:[],Pa:[],Xa:t},Pe(e,G)}var G={open:function(e){var t=q[e.node.bb];if(!t)throw new ue(43);e.Oa=t,e.seekable=!1},close:function(e){e.Oa.Xa.flush(e.Oa)},flush:function(e){e.Oa.Xa.flush(e.Oa)},read:function(e,t,n,r){if(!e.Oa||!e.Oa.Xa.nb)throw new ue(60);for(var a=0,o=0;o<r;o++){try{var i=e.Oa.Xa.nb(e.Oa)}catch(e){throw new ue(29)}if(void 0===i&&0===a)throw new ue(6);if(null==i)break;a++,t[n+o]=i}return a&&(e.node.timestamp=Date.now()),a},write:function(e,t,n,r){if(!e.Oa||!e.Oa.Xa.gb)throw new ue(60);try{for(var a=0;a<r;a++)e.Oa.Xa.gb(e.Oa,t[n+a])}catch(e){throw new ue(29)}return r&&(e.node.timestamp=Date.now()),a}},J={nb:function(e){if(!e.input.length){var t=null;if("undefined"!=typeof window&&"function"==typeof window.prompt?null!==(t=window.prompt("Input: "))&&(t+="\n"):"function"==typeof readline&&null!==(t=readline())&&(t+="\n"),!t)return null;for(var n=0,r=0;r<t.length;++r){var a=t.charCodeAt(r);55296<=a&&57343>=a&&(a=65536+((1023&a)<<10)|1023&t.charCodeAt(++r)),127>=a?++n:n=2047>=a?n+2:65535>=a?n+3:n+4}var o=(n=Array(n+1)).length;if(r=0,0<o){a=r,o=r+o-1;for(var i=0;i<t.length;++i){var s=t.charCodeAt(i);if(55296<=s&&57343>=s&&(s=65536+((1023&s)<<10)|1023&t.charCodeAt(++i)),127>=s){if(r>=o)break;n[r++]=s}else{if(2047>=s){if(r+1>=o)break;n[r++]=192|s>>6}else{if(65535>=s){if(r+2>=o)break;n[r++]=224|s>>12}else{if(r+3>=o)break;n[r++]=240|s>>18,n[r++]=128|s>>12&63}n[r++]=128|s>>6&63}n[r++]=128|63&s}}n[r]=0,t=r-a}else t=0;n.length=t,e.input=n}return e.input.shift()},gb:function(e,t){null===t||10===t?(c(g(e.Pa,0)),e.Pa=[]):0!=t&&e.Pa.push(t)},flush:function(e){e.Pa&&0<e.Pa.length&&(c(g(e.Pa,0)),e.Pa=[])}},ee={gb:function(e,t){null===t||10===t?(u(g(e.Pa,0)),e.Pa=[]):0!=t&&e.Pa.push(t)},flush:function(e){e.Pa&&0<e.Pa.length&&(u(g(e.Pa,0)),e.Pa=[])}},te={Qa:null,Sa:function(){return te.createNode(null,"/",16895,0)},createNode:function(e,t,n,r){if(24576==(61440&n)||4096==(61440&n))throw new ue(63);return te.Qa||(te.Qa={dir:{node:{Va:te.La.Va,Ra:te.La.Ra,Ya:te.La.Ya,$a:te.La.$a,sb:te.La.sb,ub:te.La.ub,tb:te.La.tb,rb:te.La.rb,cb:te.La.cb},stream:{Wa:te.Ma.Wa}},file:{node:{Va:te.La.Va,Ra:te.La.Ra},stream:{Wa:te.Ma.Wa,read:te.Ma.read,write:te.Ma.write,ib:te.Ma.ib,ob:te.Ma.ob,qb:te.Ma.qb}},link:{node:{Va:te.La.Va,Ra:te.La.Ra,Za:te.La.Za},stream:{}},jb:{node:{Va:te.La.Va,Ra:te.La.Ra},stream:ge}}),16384==(61440&(n=ye(e,t,n,r)).mode)?(n.La=te.Qa.dir.node,n.Ma=te.Qa.dir.stream,n.Ka={}):32768==(61440&n.mode)?(n.La=te.Qa.file.node,n.Ma=te.Qa.file.stream,n.Na=0,n.Ka=null):40960==(61440&n.mode)?(n.La=te.Qa.link.node,n.Ma=te.Qa.link.stream):8192==(61440&n.mode)&&(n.La=te.Qa.jb.node,n.Ma=te.Qa.jb.stream),n.timestamp=Date.now(),e&&(e.Ka[t]=n),n},Ib:function(e){if(e.Ka&&e.Ka.subarray){for(var t=[],n=0;n<e.Na;++n)t.push(e.Ka[n]);return t}return e.Ka},Jb:function(e){return e.Ka?e.Ka.subarray?e.Ka.subarray(0,e.Na):new Uint8Array(e.Ka):new Uint8Array},kb:function(e,t){var n=e.Ka?e.Ka.length:0;n>=t||(t=Math.max(t,n*(1048576>n?2:1.125)|0),0!=n&&(t=Math.max(t,256)),n=e.Ka,e.Ka=new Uint8Array(t),0<e.Na&&e.Ka.set(n.subarray(0,e.Na),0))},Ab:function(e,t){if(e.Na!=t)if(0==t)e.Ka=null,e.Na=0;else{if(!e.Ka||e.Ka.subarray){var n=e.Ka;e.Ka=new Uint8Array(new ArrayBuffer(t)),n&&e.Ka.set(n.subarray(0,Math.min(t,e.Na)))}else if(e.Ka||(e.Ka=[]),e.Ka.length>t)e.Ka.length=t;else for(;e.Ka.length<t;)e.Ka.push(0);e.Na=t}},La:{Va:function(e){var t={};return t.Hb=8192==(61440&e.mode)?e.id:1,t.Lb=e.id,t.mode=e.mode,t.Nb=1,t.uid=0,t.Kb=0,t.bb=e.bb,16384==(61440&e.mode)?t.size=4096:32768==(61440&e.mode)?t.size=e.Na:40960==(61440&e.mode)?t.size=e.link.length:t.size=0,t.Eb=new Date(e.timestamp),t.Mb=new Date(e.timestamp),t.Gb=new Date(e.timestamp),t.vb=4096,t.Fb=Math.ceil(t.size/t.vb),t},Ra:function(e,t){void 0!==t.mode&&(e.mode=t.mode),void 0!==t.timestamp&&(e.timestamp=t.timestamp),void 0!==t.size&&te.Ab(e,t.size)},Ya:function(){throw fe[44]},$a:function(e,t,n,r){return te.createNode(e,t,n,r)},sb:function(e,t,n){if(16384==(61440&e.mode)){try{var r=pe(t,n)}catch(e){}if(r)for(var a in r.Ka)throw new ue(55)}delete e.parent.Ka[e.name],e.name=n,t.Ka[n]=e,e.parent=t},ub:function(e,t){delete e.Ka[t]},tb:function(e,t){var n,r=pe(e,t);for(n in r.Ka)throw new ue(55);delete e.Ka[t]},rb:function(e){var t,n=[".",".."];for(t in e.Ka)e.Ka.hasOwnProperty(t)&&n.push(t);return n},cb:function(e,t,n){return(e=te.createNode(e,t,41471,0)).link=n,e},Za:function(e){if(40960!=(61440&e.mode))throw new ue(28);return e.link}},Ma:{read:function(e,t,n,r,a){var o=e.node.Ka;if(a>=e.node.Na)return 0;if(8<(e=Math.min(e.node.Na-a,r))&&o.subarray)t.set(o.subarray(a,a+e),n);else for(r=0;r<e;r++)t[n+r]=o[a+r];return e},write:function(e,t,n,r,a,o){if(t.buffer===y.buffer&&(o=!1),!r)return 0;if((e=e.node).timestamp=Date.now(),t.subarray&&(!e.Ka||e.Ka.subarray)){if(o)return e.Ka=t.subarray(n,n+r),e.Na=r;if(0===e.Na&&0===a)return e.Ka=new Uint8Array(t.subarray(n,n+r)),e.Na=r;if(a+r<=e.Na)return e.Ka.set(t.subarray(n,n+r),a),r}if(te.kb(e,a+r),e.Ka.subarray&&t.subarray)e.Ka.set(t.subarray(n,n+r),a);else for(o=0;o<r;o++)e.Ka[a+o]=t[n+o];return e.Na=Math.max(e.Na,a+r),r},Wa:function(e,t,n){if(1===n?t+=e.position:2===n&&32768==(61440&e.node.mode)&&(t+=e.node.Na),0>t)throw new ue(28);return t},ib:function(e,t,n){te.kb(e.node,t+n),e.node.Na=Math.max(e.node.Na,t+n)},ob:function(e,t,n,r,a,o,i){if(32768!=(61440&e.node.mode))throw new ue(43);if(n=e.node.Ka,2&i||n.buffer!==t.buffer){if((0<a||a+r<e.node.Na)&&(n=n.subarray?n.subarray(a,a+r):Array.prototype.slice.call(n,a,a+r)),e=!0,a=t.buffer==y.buffer,!(r=Qe(r)))throw new ue(48);(a?y:t).set(n,r)}else e=!1,r=n.byteOffset;return{Pb:r,Db:e}},qb:function(e,t,n,r,a){if(32768!=(61440&e.node.mode))throw new ue(43);return 2&a?0:(te.Ma.write(e,t,0,r,n,!1),0)}}},ne=null,re={},ae=[],oe=1,ie=null,se=!0,ce={},ue=null,fe={};function le(e,t){if(t=t||{},!(e=X("/",e)))return{path:"",node:null};var n,r={mb:!0,hb:0};for(n in r)void 0===t[n]&&(t[n]=r[n]);if(8<t.hb)throw new ue(32);e=F(e.split("/").filter((function(e){return!!e})),!1);var a=ne;for(r="/",n=0;n<e.length;n++){var o=n===e.length-1;if(o&&t.parent)break;if(a=pe(a,e[n]),r=V(r+"/"+e[n]),a.ab&&(!o||o&&t.mb)&&(a=a.ab.root),!o||t.lb)for(o=0;40960==(61440&a.mode);)if(a=Me(r),a=le(r=X($(r),a),{hb:t.hb}).node,40<o++)throw new ue(32)}return{path:r,node:a}}function _e(e){for(var t;;){if(e===e.parent)return e=e.Sa.pb,t?"/"!==e[e.length-1]?e+"/"+t:e+t:e;t=t?e.name+"/"+t:e.name,e=e.parent}}function de(e,t){for(var n=0,r=0;r<t.length;r++)n=(n<<5)-n+t.charCodeAt(r)|0;return(e+n>>>0)%ie.length}function pe(e,t){var n;if(n=(n=me(e,"x"))?n:e.La.Ya?0:2)throw new ue(n,e);for(n=ie[de(e.id,t)];n;n=n.zb){var r=n.name;if(n.parent.id===e.id&&r===t)return n}return e.La.Ya(e,t)}function ye(e,t,n,r){return He||((He=function(e,t,n,r){e||(e=this),this.parent=e,this.Sa=e.Sa,this.ab=null,this.id=oe++,this.name=t,this.mode=n,this.La={},this.Ma={},this.bb=r}).prototype={},Object.defineProperties(He.prototype,{read:{get:function(){return 365==(365&this.mode)},set:function(e){e?this.mode|=365:this.mode&=-366}},write:{get:function(){return 146==(146&this.mode)},set:function(e){e?this.mode|=146:this.mode&=-147}}})),function(e){var t=de(e.parent.id,e.name);e.zb=ie[t],ie[t]=e}(e=new He(e,t,n,r)),e}var he={r:0,rs:1052672,"r+":2,w:577,wx:705,xw:705,"w+":578,"wx+":706,"xw+":706,a:1089,ax:1217,xa:1217,"a+":1090,"ax+":1218,"xa+":1218};function ve(e){var t=["r","w","rw"][3&e];return 512&e&&(t+="w"),t}function me(e,t){return se?0:(-1===t.indexOf("r")||292&e.mode)&&(-1===t.indexOf("w")||146&e.mode)&&(-1===t.indexOf("x")||73&e.mode)?0:2}function we(e,t){try{return pe(e,t),20}catch(e){}return me(e,"wx")}function be(e,t){Ce||((Ce=function(){}).prototype={},Object.defineProperties(Ce.prototype,{object:{get:function(){return this.node},set:function(e){this.node=e}}}));var n,r=new Ce;for(n in e)r[n]=e[n];return e=r,t=function(e){for(e=e||0;e<=4096;e++)if(!ae[e])return e;throw new ue(33)}(t),e.Ua=t,ae[t]=e}var Ee,ge={open:function(e){e.Ma=re[e.node.bb].Ma,e.Ma.open&&e.Ma.open(e)},Wa:function(){throw new ue(70)}};function Pe(e,t){re[e]={Ma:t}}function Ae(e,t){var n="/"===t,r=!t;if(n&&ne)throw new ue(10);if(!n&&!r){var a=le(t,{mb:!1});if(t=a.path,(a=a.node).ab)throw new ue(10);if(16384!=(61440&a.mode))throw new ue(54)}t={type:e,Ob:{},pb:t,yb:[]},(e=e.Sa(t)).Sa=t,t.root=e,n?ne=e:a&&(a.ab=t,a.Sa&&a.Sa.yb.push(t))}function Te(e,t,n){var r=le(e,{parent:!0}).node;if(!(e=Q(e))||"."===e||".."===e)throw new ue(28);var a=we(r,e);if(a)throw new ue(a);if(!r.La.$a)throw new ue(63);return r.La.$a(r,e,t,n)}function Le(e){Te(e,16895,0)}function Be(e,t,n){void 0===n&&(n=t,t=438),Te(e,8192|t,n)}function xe(e,t){if(!X(e))throw new ue(44);var n=le(t,{parent:!0}).node;if(!n)throw new ue(44);var r=we(n,t=Q(t));if(r)throw new ue(r);if(!n.La.cb)throw new ue(63);n.La.cb(n,t,e)}function Me(e){if(!(e=le(e).node))throw new ue(44);if(!e.La.Za)throw new ue(28);return X(_e(e.parent),e.La.Za(e))}function Se(e,n,r,a){if(""===e)throw new ue(44);if("string"==typeof n){var o=he[n];if(void 0===o)throw Error("Unknown file open mode: "+n);n=o}if(r=64&n?4095&(void 0===r?438:r)|32768:0,"object"==typeof e)var i=e;else{e=V(e);try{i=le(e,{lb:!(131072&n)}).node}catch(e){}}if(o=!1,64&n)if(i){if(128&n)throw new ue(20)}else i=Te(e,r,0),o=!0;if(!i)throw new ue(44);if(8192==(61440&i.mode)&&(n&=-513),65536&n&&16384!=(61440&i.mode))throw new ue(54);if(!o&&(r=i?40960==(61440&i.mode)?32:16384==(61440&i.mode)&&("r"!==ve(n)||512&n)?31:me(i,ve(n)):44))throw new ue(r);if(512&n){var s;if(!(s="string"==typeof(r=i)?le(r,{lb:!0}).node:r).La.Ra)throw new ue(63);if(16384==(61440&s.mode))throw new ue(31);if(32768!=(61440&s.mode))throw new ue(28);if(r=me(s,"w"))throw new ue(r);s.La.Ra(s,{size:0,timestamp:Date.now()})}n&=-641,(a=be({node:i,path:_e(i),flags:n,seekable:!0,position:0,Ma:i.Ma,Cb:[],error:!1},a)).Ma.open&&a.Ma.open(a),!t.logReadFiles||1&n||(ze||(ze={}),e in ze||(ze[e]=1,console.log("FS.trackingDelegate error on read file: "+e)));try{ce.onOpenFile&&(i=0,1!=(2097155&n)&&(i|=1),0!=(2097155&n)&&(i|=2),ce.onOpenFile(e,i))}catch(t){console.log("FS.trackingDelegate['onOpenFile']('"+e+"', flags) threw an exception: "+t.message)}return a}function ke(e,t,n){if(null===e.Ua)throw new ue(8);if(!e.seekable||!e.Ma.Wa)throw new ue(70);if(0!=n&&1!=n&&2!=n)throw new ue(28);e.position=e.Ma.Wa(e,t,n),e.Cb=[]}function Re(e,t,n,r){var a=y;if(0>n||0>r)throw new ue(28);if(null===e.Ua)throw new ue(8);if(1==(2097155&e.flags))throw new ue(8);if(16384==(61440&e.node.mode))throw new ue(31);if(!e.Ma.read)throw new ue(28);var o=void 0!==r;if(o){if(!e.seekable)throw new ue(70)}else r=e.position;return t=e.Ma.read(e,a,t,n,r),o||(e.position+=t),t}function Ne(){ue||((ue=function(e,t){this.node=t,this.Bb=function(e){this.Ta=e},this.Bb(e),this.message="FS error"}).prototype=Error(),ue.prototype.constructor=ue,[44].forEach((function(e){fe[e]=new ue(e),fe[e].stack="<generic error, no stack>"})))}function Ke(e,t,n){e=V("/dev/"+e);var r=function(e,t){var n=0;return e&&(n|=365),t&&(n|=146),n}(!!t,!!n);Ue||(Ue=64);var a=Ue++<<8|0;Pe(a,{open:function(e){e.seekable=!1},close:function(){n&&n.buffer&&n.buffer.length&&n(10)},read:function(e,n,r,a){for(var o=0,i=0;i<a;i++){try{var s=t()}catch(e){throw new ue(29)}if(void 0===s&&0===o)throw new ue(6);if(null==s)break;o++,n[r+i]=s}return o&&(e.node.timestamp=Date.now()),o},write:function(e,t,r,a){for(var o=0;o<a;o++)try{n(t[r+o])}catch(e){throw new ue(29)}return a&&(e.node.timestamp=Date.now()),o}}),Be(e,r,a)}var Ue,He,Ce,ze,Oe={},Ye=0;function Ie(){return m[(Ye+=4)-4>>2]}function je(e){if(void 0===e&&(e=Ie()),!(e=ae[e]))throw new ue(8);return e}var De=0;Ne(),ie=Array(4096),Ae(te,"/"),Le("/tmp"),Le("/home"),Le("/home/web_user"),function(){if(Le("/dev"),Pe(259,{read:function(){return 0},write:function(e,t,n,r){return r}}),Be("/dev/null",259),Z(1280,J),Z(1536,ee),Be("/dev/tty",1280),Be("/dev/tty1",1536),"object"==typeof crypto&&"function"==typeof crypto.getRandomValues)var e=new Uint8Array(1),t=function(){return crypto.getRandomValues(e),e[0]};t||(t=function(){z("random_device")}),Ke("random",t),Ke("urandom",t),Le("/dev/shm"),Le("/dev/shm/tmp")}(),Le("/proc"),Le("/proc/self"),Le("/proc/self/fd"),Ae({Sa:function(){var e=ye("/proc/self","fd",16895,73);return e.La={Ya:function(e,t){var n=ae[+t];if(!n)throw new ue(8);return(e={parent:null,Sa:{pb:"fake"},La:{Za:function(){return n.path}}}).parent=e}},e}},"/proc/self/fd");var We={A:function(){},w:function(e,n){Ye=n;try{var r=je();switch(Ie()){case 0:var a=Ie();return 0>a?-28:Se(r.path,r.flags,0,a).Ua;case 1:case 2:return 0;case 3:return r.flags;case 4:return a=Ie(),r.flags|=a,0;case 12:return a=Ie(),v[a+0>>1]=2,0;case 13:case 14:return 0;case 16:case 8:return-28;case 9:return t.___errno_location&&(m[t.___errno_location()>>2]=28),-1;default:return-28}}catch(e){return void 0!==Oe&&e instanceof ue||z(e),-e.Ta}},F:function(e,t){Ye=t;try{return Re(je(),Ie(),Ie())}catch(e){return void 0!==Oe&&e instanceof ue||z(e),-e.Ta}},z:function(e,t){Ye=t;try{var n=Ie();return Se(n?g(h,n,void 0):"",Ie(),Ie()).Ua}catch(e){return void 0!==Oe&&e instanceof ue||z(e),-e.Ta}},D:function(e,t){Ye=t;try{var n=je(),r=Ie();switch(r){case 21509:case 21505:return n.Oa?0:-59;case 21510:case 21511:case 21512:case 21506:case 21507:case 21508:return n.Oa?0:-59;case 21519:if(!n.Oa)return-59;var a=Ie();return m[a>>2]=0;case 21520:return n.Oa?-28:-59;case 21531:if(e=a=Ie(),!n.Ma.xb)throw new ue(59);return n.Ma.xb(n,r,e);case 21523:case 21524:return n.Oa?0:-59;default:z("bad ioctl syscall "+r)}}catch(e){return void 0!==Oe&&e instanceof ue||z(e),-e.Ta}},s:function(){},u:function(){z()},h:function(e,t){throw $e(e,t||1),"longjmp"},G:function(e,t,n){h.set(h.subarray(t,t+n),e)},H:function(e){if(2147418112<e)return!1;for(var t=Math.max(y.length,16777216);t<e;)t=536870912>=t?P(2*t):Math.min(P((3*t+2147483648)/4),2147418112);e:{try{d.grow(t-p.byteLength+65535>>16),A(d.buffer);var n=1;break e}catch(e){}n=void 0}return!!n},m:function(e){!l&&(b=!0,t.onExit)&&t.onExit(e),o(e,new dt(e))},t:function(e){try{var t=je(e);if(null===t.Ua)throw new ue(8);t.fb&&(t.fb=null);try{t.Ma.close&&t.Ma.close(t)}catch(e){throw e}finally{ae[t.Ua]=null}return t.Ua=null,0}catch(e){return void 0!==Oe&&e instanceof ue||z(e),e.Ta}},C:function(e,t,n,r){try{e:{for(var a=je(e),o=e=0;o<n;o++){var i=m[t+(8*o+4)>>2],s=Re(a,m[t+8*o>>2],i,void 0);if(0>s){var c=-1;break e}if(e+=s,s<i)break}c=e}return m[r>>2]=c,0}catch(e){return void 0!==Oe&&e instanceof ue||z(e),e.Ta}},B:function(e,t,n,r,a){try{var o=je(e);return-9007199254740992>=(e=4294967296*n+(t>>>0))||9007199254740992<=e?-61:(ke(o,e,r),I=[o.position>>>0,(Y=o.position,1<=+R(Y)?0<Y?(0|U(+K(Y/4294967296),4294967295))>>>0:~~+N((Y-+(~~Y>>>0))/4294967296)>>>0:0)],m[a>>2]=I[0],m[a+4>>2]=I[1],o.fb&&0===e&&0===r&&(o.fb=null),0)}catch(e){return void 0!==Oe&&e instanceof ue||z(e),e.Ta}},E:function(e,t,n,r){try{e:{for(var a=je(e),o=e=0;o<n;o++){var i=a,s=m[t+8*o>>2],c=m[t+(8*o+4)>>2],u=void 0,f=y;if(0>c||0>u)throw new ue(28);if(null===i.Ua)throw new ue(8);if(0==(2097155&i.flags))throw new ue(8);if(16384==(61440&i.node.mode))throw new ue(31);if(!i.Ma.write)throw new ue(28);1024&i.flags&&ke(i,0,2);var l=void 0!==u;if(l){if(!i.seekable)throw new ue(70)}else u=i.position;var _=i.Ma.write(i,f,s,c,u,void 0);l||(i.position+=_);try{i.path&&ce.onWriteToFile&&ce.onWriteToFile(i.path)}catch(e){console.log("FS.trackingDelegate['onWriteToFile']('"+i.path+"') threw an exception: "+e.message)}var d=_;if(0>d){var p=-1;break e}e+=d}p=e}return m[r>>2]=p,0}catch(e){return void 0!==Oe&&e instanceof ue||z(e),e.Ta}},a:function(){return 0|_},x:function(e){var t=Date.now();return m[e>>2]=t/1e3|0,m[e+4>>2]=t%1e3*1e3|0,0},g:function(e){var t=ft();try{return ot(e)}catch(e){if(_t(t),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},j:function(e,t){var n=ft();try{return it(e,t)}catch(e){if(_t(n),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},i:function(e,t,n){var r=ft();try{return st(e,t,n)}catch(e){if(_t(r),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},q:function(e,t,n,r){var a=ft();try{return ct(e,t,n,r)}catch(e){if(_t(a),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},y:function(e,t,n,r,a){var o=ft();try{return ut(e,t,n,r,a)}catch(e){if(_t(o),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},n:function(e){var t=ft();try{qe(e)}catch(e){if(_t(t),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},e:function(e,t){var n=ft();try{Ze(e,t)}catch(e){if(_t(n),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},d:function(e,t,n){var r=ft();try{Ge(e,t,n)}catch(e){if(_t(r),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},f:function(e,t,n,r){var a=ft();try{Je(e,t,n,r)}catch(e){if(_t(a),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},l:function(e,t,n,r,a){var o=ft();try{et(e,t,n,r,a)}catch(e){if(_t(o),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},o:function(e,t,n,r,a,o){var i=ft();try{tt(e,t,n,r,a,o)}catch(e){if(_t(i),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},p:function(e,t,n,r,a,o,i){var s=ft();try{nt(e,t,n,r,a,o,i)}catch(e){if(_t(s),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},r:function(e,t,n,r,a,o,i,s){var c=ft();try{rt(e,t,n,r,a,o,i,s)}catch(e){if(_t(c),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},v:function(e,t,n,r,a,o,i,s,c){var u=ft();try{at(e,t,n,r,a,o,i,s,c)}catch(e){if(_t(u),e!==e+0&&"longjmp"!==e)throw e;$e(1,0)}},memory:d,k:function e(t,n,r,a){n|=0,r|=0,a|=0;var o=0;for(De=De+1|0,m[(t|=0)>>2]=De;(0|o)<(0|a);){if(0==(0|m[r+(o<<3)>>2]))return m[r+(o<<3)>>2]=De,m[r+(4+(o<<3))>>2]=n,m[r+(8+(o<<3))>>2]=0,_=0|a,0|r;o=o+1|0}return r=0|e(0|t,0|n,0|(r=0|Xe(0|r,8*(1+(a=2*a|0)|0)|0)),0|a),_=0|a,0|r},c:function(e){_=0|e},table:w,b:function(e,t,n){e|=0,t|=0,n|=0;for(var r,a=0;(0|a)<(0|n)&&0!=(0|(r=0|m[t+(a<<3)>>2]));){if((0|r)==(0|e))return 0|m[t+(4+(a<<3))>>2];a=a+1|0}return 0}},Fe=function(){function e(e){t.asm=e.exports,H--,t.monitorRunDependencies&&t.monitorRunDependencies(H),0==H&&C&&(e=C,C=null,e())}function n(t){e(t.instance)}function r(e){return(f||"function"!=typeof fetch?new Promise((function(e){e(W())})):fetch(j,{credentials:"same-origin"}).then((function(e){if(!e.ok)throw"failed to load wasm binary file at '"+j+"'";return e.arrayBuffer()})).catch((function(){return W()}))).then((function(e){return WebAssembly.instantiate(e,a)})).then(e,(function(e){u("failed to asynchronously prepare wasm: "+e),z(e)}))}var a={env:We,wasi_snapshot_preview1:We};if(H++,t.monitorRunDependencies&&t.monitorRunDependencies(H),t.instantiateWasm)try{return t.instantiateWasm(a,e)}catch(e){return u("Module.instantiateWasm callback failed with error: "+e),!1}return function(){if(f||"function"!=typeof WebAssembly.instantiateStreaming||O()||"function"!=typeof fetch)return r(n);fetch(j,{credentials:"same-origin"}).then((function(e){return WebAssembly.instantiateStreaming(e,a).then(n,(function(e){u("wasm streaming compile failed: "+e),u("falling back to ArrayBuffer instantiation"),r(n)}))}))}(),{}}();t.asm=Fe;var Ve=t.___wasm_call_ctors=function(){return t.asm.I.apply(null,arguments)};t._vscp_error_ctx_size=function(){return t.asm.J.apply(null,arguments)},t._vscp_error_reset=function(){return t.asm.K.apply(null,arguments)},t._vscp_error_status=function(){return t.asm.L.apply(null,arguments)},t._vscp_pythia_configure=function(){return t.asm.M.apply(null,arguments)},t._vscp_pythia_cleanup=function(){return t.asm.N.apply(null,arguments)},t._vscp_pythia_blinded_password_buf_len=function(){return t.asm.O.apply(null,arguments)},t._vscp_pythia_deblinded_password_buf_len=function(){return t.asm.P.apply(null,arguments)},t._vscp_pythia_blinding_secret_buf_len=function(){return t.asm.Q.apply(null,arguments)},t._vscp_pythia_transformation_private_key_buf_len=function(){return t.asm.R.apply(null,arguments)},t._vscp_pythia_transformation_public_key_buf_len=function(){return t.asm.S.apply(null,arguments)},t._vscp_pythia_transformed_password_buf_len=function(){return t.asm.T.apply(null,arguments)},t._vscp_pythia_transformed_tweak_buf_len=function(){return t.asm.U.apply(null,arguments)},t._vscp_pythia_proof_value_buf_len=function(){return t.asm.V.apply(null,arguments)},t._vscp_pythia_password_update_token_buf_len=function(){return t.asm.W.apply(null,arguments)},t._vscp_pythia_blind=function(){return t.asm.X.apply(null,arguments)},t._vscp_pythia_deblind=function(){return t.asm.Y.apply(null,arguments)},t._vscp_pythia_compute_transformation_key_pair=function(){return t.asm.Z.apply(null,arguments)},t._vscp_pythia_transform=function(){return t.asm._.apply(null,arguments)},t._vscp_pythia_prove=function(){return t.asm.$.apply(null,arguments)},t._vscp_pythia_verify=function(){return t.asm.aa.apply(null,arguments)},t._vscp_pythia_get_password_update_token=function(){return t.asm.ba.apply(null,arguments)},t._vscp_pythia_update_deblinded_with_token=function(){return t.asm.ca.apply(null,arguments)},t._vsc_buffer_new=function(){return t.asm.da.apply(null,arguments)},t._vsc_buffer_new_with_capacity=function(){return t.asm.ea.apply(null,arguments)},t._vsc_buffer_delete=function(){return t.asm.fa.apply(null,arguments)},t._vsc_buffer_data=function(){return t.asm.ga.apply(null,arguments)},t._vsc_buffer_make_secure=function(){return t.asm.ha.apply(null,arguments)},t._vsc_buffer_bytes=function(){return t.asm.ia.apply(null,arguments)},t._vsc_buffer_len=function(){return t.asm.ja.apply(null,arguments)},t._vsc_data_ctx_size=function(){return t.asm.ka.apply(null,arguments)},t._vsc_data=function(){return t.asm.la.apply(null,arguments)},t._vsc_data_len=function(){return t.asm.ma.apply(null,arguments)},t._vsc_data_bytes=function(){return t.asm.na.apply(null,arguments)},t.___errno_location=function(){return t.asm.oa.apply(null,arguments)};var $e=t._setThrew=function(){return t.asm.pa.apply(null,arguments)},Qe=t._malloc=function(){return t.asm.qa.apply(null,arguments)};t._free=function(){return t.asm.ra.apply(null,arguments)};var Xe=t._realloc=function(){return t.asm.sa.apply(null,arguments)},qe=t.dynCall_v=function(){return t.asm.ta.apply(null,arguments)},Ze=t.dynCall_vi=function(){return t.asm.ua.apply(null,arguments)},Ge=t.dynCall_vii=function(){return t.asm.va.apply(null,arguments)},Je=t.dynCall_viii=function(){return t.asm.wa.apply(null,arguments)},et=t.dynCall_viiii=function(){return t.asm.xa.apply(null,arguments)},tt=t.dynCall_viiiii=function(){return t.asm.ya.apply(null,arguments)},nt=t.dynCall_viiiiii=function(){return t.asm.za.apply(null,arguments)},rt=t.dynCall_viiiiiii=function(){return t.asm.Aa.apply(null,arguments)},at=t.dynCall_viiiiiiii=function(){return t.asm.Ba.apply(null,arguments)},ot=t.dynCall_i=function(){return t.asm.Ca.apply(null,arguments)},it=t.dynCall_ii=function(){return t.asm.Da.apply(null,arguments)},st=t.dynCall_iii=function(){return t.asm.Ea.apply(null,arguments)},ct=t.dynCall_iiii=function(){return t.asm.Fa.apply(null,arguments)},ut=t.dynCall_iiiii=function(){return t.asm.Ga.apply(null,arguments)},ft=t.stackSave=function(){return t.asm.Ha.apply(null,arguments)};t.stackAlloc=function(){return t.asm.Ia.apply(null,arguments)};var lt,_t=t.stackRestore=function(){return t.asm.Ja.apply(null,arguments)};function dt(e){this.name="ExitStatus",this.message="Program terminated with exit("+e+")",this.status=e}function pt(){function e(){if(!lt&&(lt=!0,!b)){if(t.noFSInit||Ee||(Ee=!0,Ne(),t.stdin=t.stdin,t.stdout=t.stdout,t.stderr=t.stderr,t.stdin?Ke("stdin",t.stdin):xe("/dev/tty","/dev/stdin"),t.stdout?Ke("stdout",null,t.stdout):xe("/dev/tty","/dev/stdout"),t.stderr?Ke("stderr",null,t.stderr):xe("/dev/tty1","/dev/stderr"),Se("/dev/stdin","r"),Se("/dev/stdout","w"),Se("/dev/stderr","w")),L(x),se=!1,L(M),t.onRuntimeInitialized&&t.onRuntimeInitialized(),t.postRun)for("function"==typeof t.postRun&&(t.postRun=[t.postRun]);t.postRun.length;){var e=t.postRun.shift();S.unshift(e)}L(S)}}if(!(0<H)){if(t.preRun)for("function"==typeof t.preRun&&(t.preRun=[t.preRun]);t.preRun.length;)k();L(B),0<H||(t.setStatus?(t.setStatus("Running..."),setTimeout((function(){setTimeout((function(){t.setStatus("")}),1),e()}),1)):e())}}if(t.asm=Fe,t.then=function(e){if(lt)e(t);else{var n=t.onRuntimeInitialized;t.onRuntimeInitialized=function(){n&&n(),e(t)}}return t},C=function e(){lt||pt(),lt||(C=e)},t.run=pt,t.preInit)for("function"==typeof t.preInit&&(t.preInit=[t.preInit]);0<t.preInit.length;)t.preInit.pop()();return l=!0,pt(),e});e.exports=r}));var t=(e,t)=>{class n extends Error{constructor(e){super(e),this.name="PythiaError",this.message=e}static handleStatusCode(e){if(0!=e){if(-1==e)throw new n("This error should not be returned if assertions is enabled.");if(-200==e)throw new n("Underlying pythia library returns -1.");if(-202==e)throw new n("Underlying random number generator failed.");throw new n("Unexpected status code:"+e)}}}return n};function n(e,t){if(!("number"==typeof t||t instanceof Number))throw new TypeError(`'${e}' is not a number`);if(Number.isNaN(t))throw new TypeError(`'${e}' is NaN`);if(t===1/0)throw new TypeError(`'${e}' is Infinity`);if(t===-1/0)throw new TypeError(`'${e}' is -Infinity`)}function r(e,t){if(n(e,t),0==t)throw new TypeError(`'${e}' is NULL`)}var a={ensureNumber:n,ensureString:function(e,t){if(!("string"==typeof t||t instanceof String))throw new TypeError(`'${e}' is not a string`)},ensureBoolean:function(e,t){if("boolean"!=typeof t)throw new TypeError(`'${e}' is not a boolean`)},ensureByteArray:function(e,t){if(!(t instanceof Uint8Array))throw new TypeError(`'${e}' is not an Uint8Array`)},ensureClass:function(e,t,n){if(!(t instanceof n))throw new TypeError(`'${e}' is not an instance of the class ${n.name}`);r(e,t.ctxPtr)},ensureNotNull:r,ensureImplementInterface:function(e,t,n,a,o){if(r(e,t.ctxPtr),!o.isImplemented(t.ctxPtr,a))throw new TypeError(`'${e}' does not implement interface '${n}'`)}};var o=(e,t)=>{class n{static configure(){const n=e._vscp_pythia_configure();t.PythiaError.handleStatusCode(n)}static cleanup(){e._vscp_pythia_cleanup()}static blindedPasswordBufLen(){let t;return t=e._vscp_pythia_blinded_password_buf_len(),t}static deblindedPasswordBufLen(){let t;return t=e._vscp_pythia_deblinded_password_buf_len(),t}static blindingSecretBufLen(){let t;return t=e._vscp_pythia_blinding_secret_buf_len(),t}static transformationPrivateKeyBufLen(){let t;return t=e._vscp_pythia_transformation_private_key_buf_len(),t}static transformationPublicKeyBufLen(){let t;return t=e._vscp_pythia_transformation_public_key_buf_len(),t}static transformedPasswordBufLen(){let t;return t=e._vscp_pythia_transformed_password_buf_len(),t}static transformedTweakBufLen(){let t;return t=e._vscp_pythia_transformed_tweak_buf_len(),t}static proofValueBufLen(){let t;return t=e._vscp_pythia_proof_value_buf_len(),t}static passwordUpdateTokenBufLen(){let t;return t=e._vscp_pythia_password_update_token_buf_len(),t}static blind(r){a.ensureByteArray("password",r);const o=r.length*r.BYTES_PER_ELEMENT,i=e._malloc(o);e.HEAP8.set(r,i);const s=e._vsc_data_ctx_size(),c=e._malloc(s);e._vsc_data(c,i,o);const u=n.blindedPasswordBufLen(),f=e._vsc_buffer_new_with_capacity(u),l=n.blindingSecretBufLen(),_=e._vsc_buffer_new_with_capacity(l);try{const n=e._vscp_pythia_blind(c,f,_);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(f),a=e._vsc_buffer_len(f),o=e.HEAPU8.slice(r,r+a),s=e._vsc_buffer_bytes(_),u=e._vsc_buffer_len(_);return{blindedPassword:o,blindingSecret:e.HEAPU8.slice(s,s+u)}}finally{e._free(i),e._free(c),e._vsc_buffer_delete(f),e._vsc_buffer_delete(_)}}static deblind(r,o){a.ensureByteArray("transformedPassword",r),a.ensureByteArray("blindingSecret",o);const i=r.length*r.BYTES_PER_ELEMENT,s=e._malloc(i);e.HEAP8.set(r,s);const c=e._vsc_data_ctx_size(),u=e._malloc(c);e._vsc_data(u,s,i);const f=o.length*o.BYTES_PER_ELEMENT,l=e._malloc(f);e.HEAP8.set(o,l);const _=e._vsc_data_ctx_size(),d=e._malloc(_);e._vsc_data(d,l,f);const p=n.deblindedPasswordBufLen(),y=e._vsc_buffer_new_with_capacity(p);try{const n=e._vscp_pythia_deblind(u,d,y);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(y),a=e._vsc_buffer_len(y);return e.HEAPU8.slice(r,r+a)}finally{e._free(s),e._free(u),e._free(l),e._free(d),e._vsc_buffer_delete(y)}}static computeTransformationKeyPair(r,o,i){a.ensureByteArray("transformationKeyId",r),a.ensureByteArray("pythiaSecret",o),a.ensureByteArray("pythiaScopeSecret",i);const s=r.length*r.BYTES_PER_ELEMENT,c=e._malloc(s);e.HEAP8.set(r,c);const u=e._vsc_data_ctx_size(),f=e._malloc(u);e._vsc_data(f,c,s);const l=o.length*o.BYTES_PER_ELEMENT,_=e._malloc(l);e.HEAP8.set(o,_);const d=e._vsc_data_ctx_size(),p=e._malloc(d);e._vsc_data(p,_,l);const y=i.length*i.BYTES_PER_ELEMENT,h=e._malloc(y);e.HEAP8.set(i,h);const v=e._vsc_data_ctx_size(),m=e._malloc(v);e._vsc_data(m,h,y);const w=n.transformationPrivateKeyBufLen(),b=e._vsc_buffer_new_with_capacity(w),E=n.transformationPublicKeyBufLen(),g=e._vsc_buffer_new_with_capacity(E);try{const n=e._vscp_pythia_compute_transformation_key_pair(f,p,m,b,g);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(b),a=e._vsc_buffer_len(b),o=e.HEAPU8.slice(r,r+a),i=e._vsc_buffer_bytes(g),s=e._vsc_buffer_len(g);return{transformationPrivateKey:o,transformationPublicKey:e.HEAPU8.slice(i,i+s)}}finally{e._free(c),e._free(f),e._free(_),e._free(p),e._free(h),e._free(m),e._vsc_buffer_delete(b),e._vsc_buffer_delete(g)}}static transform(r,o,i){a.ensureByteArray("blindedPassword",r),a.ensureByteArray("tweak",o),a.ensureByteArray("transformationPrivateKey",i);const s=r.length*r.BYTES_PER_ELEMENT,c=e._malloc(s);e.HEAP8.set(r,c);const u=e._vsc_data_ctx_size(),f=e._malloc(u);e._vsc_data(f,c,s);const l=o.length*o.BYTES_PER_ELEMENT,_=e._malloc(l);e.HEAP8.set(o,_);const d=e._vsc_data_ctx_size(),p=e._malloc(d);e._vsc_data(p,_,l);const y=i.length*i.BYTES_PER_ELEMENT,h=e._malloc(y);e.HEAP8.set(i,h);const v=e._vsc_data_ctx_size(),m=e._malloc(v);e._vsc_data(m,h,y);const w=n.transformedPasswordBufLen(),b=e._vsc_buffer_new_with_capacity(w),E=n.transformedTweakBufLen(),g=e._vsc_buffer_new_with_capacity(E);try{const n=e._vscp_pythia_transform(f,p,m,b,g);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(b),a=e._vsc_buffer_len(b),o=e.HEAPU8.slice(r,r+a),i=e._vsc_buffer_bytes(g),s=e._vsc_buffer_len(g);return{transformedPassword:o,transformedTweak:e.HEAPU8.slice(i,i+s)}}finally{e._free(c),e._free(f),e._free(_),e._free(p),e._free(h),e._free(m),e._vsc_buffer_delete(b),e._vsc_buffer_delete(g)}}static prove(r,o,i,s,c){a.ensureByteArray("transformedPassword",r),a.ensureByteArray("blindedPassword",o),a.ensureByteArray("transformedTweak",i),a.ensureByteArray("transformationPrivateKey",s),a.ensureByteArray("transformationPublicKey",c);const u=r.length*r.BYTES_PER_ELEMENT,f=e._malloc(u);e.HEAP8.set(r,f);const l=e._vsc_data_ctx_size(),_=e._malloc(l);e._vsc_data(_,f,u);const d=o.length*o.BYTES_PER_ELEMENT,p=e._malloc(d);e.HEAP8.set(o,p);const y=e._vsc_data_ctx_size(),h=e._malloc(y);e._vsc_data(h,p,d);const v=i.length*i.BYTES_PER_ELEMENT,m=e._malloc(v);e.HEAP8.set(i,m);const w=e._vsc_data_ctx_size(),b=e._malloc(w);e._vsc_data(b,m,v);const E=s.length*s.BYTES_PER_ELEMENT,g=e._malloc(E);e.HEAP8.set(s,g);const P=e._vsc_data_ctx_size(),A=e._malloc(P);e._vsc_data(A,g,E);const T=c.length*c.BYTES_PER_ELEMENT,L=e._malloc(T);e.HEAP8.set(c,L);const B=e._vsc_data_ctx_size(),x=e._malloc(B);e._vsc_data(x,L,T);const M=n.proofValueBufLen(),S=e._vsc_buffer_new_with_capacity(M),k=n.proofValueBufLen(),R=e._vsc_buffer_new_with_capacity(k);try{const n=e._vscp_pythia_prove(_,h,b,A,x,S,R);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(S),a=e._vsc_buffer_len(S),o=e.HEAPU8.slice(r,r+a),i=e._vsc_buffer_bytes(R),s=e._vsc_buffer_len(R);return{proofValueC:o,proofValueU:e.HEAPU8.slice(i,i+s)}}finally{e._free(f),e._free(_),e._free(p),e._free(h),e._free(m),e._free(b),e._free(g),e._free(A),e._free(L),e._free(x),e._vsc_buffer_delete(S),e._vsc_buffer_delete(R)}}static verify(n,r,o,i,s,c){a.ensureByteArray("transformedPassword",n),a.ensureByteArray("blindedPassword",r),a.ensureByteArray("tweak",o),a.ensureByteArray("transformationPublicKey",i),a.ensureByteArray("proofValueC",s),a.ensureByteArray("proofValueU",c);const u=n.length*n.BYTES_PER_ELEMENT,f=e._malloc(u);e.HEAP8.set(n,f);const l=e._vsc_data_ctx_size(),_=e._malloc(l);e._vsc_data(_,f,u);const d=r.length*r.BYTES_PER_ELEMENT,p=e._malloc(d);e.HEAP8.set(r,p);const y=e._vsc_data_ctx_size(),h=e._malloc(y);e._vsc_data(h,p,d);const v=o.length*o.BYTES_PER_ELEMENT,m=e._malloc(v);e.HEAP8.set(o,m);const w=e._vsc_data_ctx_size(),b=e._malloc(w);e._vsc_data(b,m,v);const E=i.length*i.BYTES_PER_ELEMENT,g=e._malloc(E);e.HEAP8.set(i,g);const P=e._vsc_data_ctx_size(),A=e._malloc(P);e._vsc_data(A,g,E);const T=s.length*s.BYTES_PER_ELEMENT,L=e._malloc(T);e.HEAP8.set(s,L);const B=e._vsc_data_ctx_size(),x=e._malloc(B);e._vsc_data(x,L,T);const M=c.length*c.BYTES_PER_ELEMENT,S=e._malloc(M);e.HEAP8.set(c,S);const k=e._vsc_data_ctx_size(),R=e._malloc(k);e._vsc_data(R,S,M);const N=e._vscp_error_ctx_size(),K=e._malloc(N);let U;e._vscp_error_reset(K);try{U=e._vscp_pythia_verify(_,h,b,A,x,R,K);const n=e._vscp_error_status(K);return t.PythiaError.handleStatusCode(n),!!U}finally{e._free(f),e._free(_),e._free(p),e._free(h),e._free(m),e._free(b),e._free(g),e._free(A),e._free(L),e._free(x),e._free(S),e._free(R),e._free(K)}}static getPasswordUpdateToken(r,o){a.ensureByteArray("previousTransformationPrivateKey",r),a.ensureByteArray("newTransformationPrivateKey",o);const i=r.length*r.BYTES_PER_ELEMENT,s=e._malloc(i);e.HEAP8.set(r,s);const c=e._vsc_data_ctx_size(),u=e._malloc(c);e._vsc_data(u,s,i);const f=o.length*o.BYTES_PER_ELEMENT,l=e._malloc(f);e.HEAP8.set(o,l);const _=e._vsc_data_ctx_size(),d=e._malloc(_);e._vsc_data(d,l,f);const p=n.passwordUpdateTokenBufLen(),y=e._vsc_buffer_new_with_capacity(p);try{const n=e._vscp_pythia_get_password_update_token(u,d,y);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(y),a=e._vsc_buffer_len(y);return e.HEAPU8.slice(r,r+a)}finally{e._free(s),e._free(u),e._free(l),e._free(d),e._vsc_buffer_delete(y)}}static updateDeblindedWithToken(r,o){a.ensureByteArray("deblindedPassword",r),a.ensureByteArray("passwordUpdateToken",o);const i=r.length*r.BYTES_PER_ELEMENT,s=e._malloc(i);e.HEAP8.set(r,s);const c=e._vsc_data_ctx_size(),u=e._malloc(c);e._vsc_data(u,s,i);const f=o.length*o.BYTES_PER_ELEMENT,l=e._malloc(f);e.HEAP8.set(o,l);const _=e._vsc_data_ctx_size(),d=e._malloc(_);e._vsc_data(d,l,f);const p=n.deblindedPasswordBufLen(),y=e._vsc_buffer_new_with_capacity(p);try{const n=e._vscp_pythia_update_deblinded_with_token(u,d,y);t.PythiaError.handleStatusCode(n);const r=e._vsc_buffer_bytes(y),a=e._vsc_buffer_len(y);return e.HEAPU8.slice(r,r+a)}finally{e._free(s),e._free(u),e._free(l),e._free(d),e._vsc_buffer_delete(y)}}}return n};var i=()=>{const n=new e;return new Promise((e,r)=>{n.onRuntimeInitialized=()=>{const r={};r.PythiaError=t(),r.Pythia=o(n,r),e(r)},n.onAbort=e=>{r(new Error(e))}})};export default i;
