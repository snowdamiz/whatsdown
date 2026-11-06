import {createRequire} from 'node:module';
import {readFileSync,writeFileSync} from 'node:fs';
const root=process.argv[2];
if (!root) throw Error('Expected mobile package path');
const require=createRequire(root+'/package.json');const babel=require('@babel/core');const commonjs=require('@babel/plugin-transform-modules-commonjs');
const wrap=(path,dependency='')=>`(function(){const exports={};${dependency}${babel.transformSync(readFileSync(path,'utf8'),{filename:path,babelrc:false,configFile:false,plugins:[commonjs]}).code};return exports;})()`;
const p=root+'/node_modules/@tauri-apps/api/';
const result='const tauriTslib='+wrap(p+'external/tslib/tslib.es6.js')+';\nconst tauriCore='+wrap(p+'core.js','const require=()=>tauriTslib;')+';\n';
process.stdout.write(result);
