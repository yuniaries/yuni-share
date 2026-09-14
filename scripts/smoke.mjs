// Isolated smoke test: launches a fresh server and never touches an existing deployment.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {webcrypto as c,randomUUID} from 'node:crypto';
import {issueEnrollment} from '../enrollment.mjs';
import {gzipSync} from 'node:zlib';
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'share-smoke-'));
const base='http://localhost:18292';
const proc=spawn(process.execPath,['server.mjs'],{env:{...process.env,PORT:'18292',PUBLIC_URL:base,DATA_ROOT:dir,DISK_RESERVE_BYTES:'0',ADMIN_PASSWORD:''},stdio:['ignore','pipe','pipe']});
let cookie='';
const enc=new TextEncoder(),b64=x=>Buffer.from(x).toString('base64url');
async function req(url,method='GET',body){const r=await fetch(base+url,{method,headers:{Origin:base,...(cookie?{Cookie:cookie}:{}),...(body?{'Content-Type':body instanceof Uint8Array?'application/octet-stream':'application/json'}:{})},body:body?(body instanceof Uint8Array?body:JSON.stringify(body)):undefined});return r;}
async function ok(r,status=200){assert.equal(r.status,status,await r.clone().text());return r;}
try {
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Startup timeout')),15000);proc.stdout.on('data',d=>{if(String(d).includes('listening')){clearTimeout(timer);resolve();}});proc.once('exit',code=>{clearTimeout(timer);reject(new Error('Server exited '+code));});proc.stderr.on('data',d=>process.stderr.write(d));});
 await ok(await req('/'));
 const email='smoke@example.com',password='Only-for-local-smoke-2026';
 const rawVault=c.getRandomValues(new Uint8Array(32)),salt=c.getRandomValues(new Uint8Array(16)),iv=c.getRandomValues(new Uint8Array(12));
 const pw=await c.subtle.importKey('raw',enc.encode('independent vault phrase'),'PBKDF2',false,['deriveKey']);
 const wrap=await c.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:600000},pw,{name:'AES-GCM',length:256},false,['encrypt']);
 const wrapped=await c.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode('yuni-share:vault-wrap:v1')},wrap,rawVault);
 const r=await ok(await req('/api/register','POST',{email,username:'smoke_user',password,code:issueEnrollment(dir,email),encryption:{version:1,iterations:600000,salt:b64(salt),iv:b64(iv),wrappedKey:b64(wrapped)}}),201);
 cookie=r.headers.get('set-cookie').split(';')[0];
 await ok(await req('/api/me'));
 const id=randomUUID(),nonce=c.getRandomValues(new Uint8Array(8)),rawKey=c.getRandomValues(new Uint8Array(32));
 const key=await c.subtle.importKey('raw',rawKey,'AES-GCM',false,['encrypt','decrypt']);
 const vault=await c.subtle.importKey('raw',rawVault,'AES-GCM',false,['encrypt']);
 const plains=[new Uint8Array(16*1024*1024).fill(65),enc.encode('last chunk')],chunks=[];
 for(let i=0;i<2;i++){const compressed=gzipSync(plains[i]);const smaller=compressed.length<plains[i].length;const framed=Buffer.concat([Buffer.from([smaller?1:0]),smaller?compressed:plains[i]]);const v=new Uint8Array(12);v.set(nonce);new DataView(v.buffer).setUint32(8,i,false);chunks.push(new Uint8Array(await c.subtle.encrypt({name:'AES-GCM',iv:v,additionalData:enc.encode('yuni-share:file-chunk:v1:'+id+':'+i)},key,framed)));}
 const miv=c.getRandomValues(new Uint8Array(12));
 const logicalSize=plains[0].length+plains[1].length;
 const meta=await c.subtle.encrypt({name:'AES-GCM',iv:miv,additionalData:enc.encode('yuni-share:file-metadata:v1:'+id)},vault,enc.encode(JSON.stringify({version:2,name:'smoke.txt',mime:'text/plain',size:logicalSize,plainChunkSize:plains[0].length,compression:{version:1,algorithm:'gzip',framing:'per-chunk'},fileKey:b64(rawKey),fileNonce:b64(nonce)})));
 const upload=await (await ok(await req('/api/uploads','POST',{id,size:logicalSize+34,logicalSize,compressionVersion:1,encryption:{version:1,metadata:b64(meta),metadataIv:b64(miv)}}),201)).json();
 assert.equal(upload.chunkCount,2);
 for(let i=0;i<2;i++)await ok(await req(`/api/uploads/${id}/chunks/${i}`,'PUT',chunks[i]));
 const file=await (await ok(await req(`/api/uploads/${id}/complete`,'POST',{}),201)).json();
 for(let i=0;i<2;i++){const got=new Uint8Array(await (await ok(await req(`/api/files/${file.id}/chunks/${i}`))).arrayBuffer());assert.deepEqual(got,chunks[i]);}
 await ok(await req('/api/password-reset/request','POST',{email}),501);
 await ok(await req('/api/payment-orders','POST',{}),501);
 await ok(await req('/api/logout','POST',{}));cookie='';
 await ok(await req(`/api/files/${file.id}/chunks/0`),401);
 await ok(await req('/api/login','POST',{email,password}));
 console.log('PASS: startup, register, session, 2-chunk upload/complete/download, logout, unauthenticated rejection, login, disabled integrations.');
}finally{proc.kill('SIGTERM');await new Promise(resolve=>{if(proc.exitCode!==null)resolve();else proc.once('exit',resolve);});fs.rmSync(dir,{recursive:true,force:true});}
