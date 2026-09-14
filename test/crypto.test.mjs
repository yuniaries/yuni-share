import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
const names=['randomBytes','chunkIv','chunkAad','compressionSupported','gzipChunk','gunzipChunk','encodeFileChunk','decodeFileChunk','encryptChunk','derivePasswordWrappingKey'];
const snippets=names.map(name=>{
 const m=source.match(new RegExp('^(?:async )?function '+name+'\\([^]*?^\\}', 'm'));
 if(!m)throw new Error('Missing production function: '+name);
 return m[0];
});
const ctx=vm.createContext({crypto:webcrypto,TextEncoder,Uint8Array,DataView,Blob,Response,CompressionStream,DecompressionStream,Map});
vm.runInContext("const encoder=new TextEncoder(); const FILE_COMPRESSION_ALGORITHM='gzip'; const ENCRYPTION_VERSION=1;"+snippets.join('\n'),ctx);
test('actual frontend chunk encryption round-trip, AAD binding, and tamper rejection',async()=>{
 const key=await webcrypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const bytes=new TextEncoder().encode('auditable file '.repeat(1000));
 const task={id:'test-upload',file:new Blob([bytes]),plainChunkSize:bytes.length,fileNonce:webcrypto.getRandomValues(new Uint8Array(8)),fileKey:key};
 const result=await ctx.encryptChunk(task,0);
 const ciphertext=new Uint8Array(await result.blob.arrayBuffer());
 const params={name:'AES-GCM',iv:ctx.chunkIv(task.fileNonce,0),additionalData:ctx.chunkAad(task.id,0)};
 const plain=await webcrypto.subtle.decrypt(params,key,ciphertext);
 assert.deepEqual(Buffer.from(await ctx.decodeFileChunk(plain,{version:2},bytes.length)),Buffer.from(bytes));
 await assert.rejects(webcrypto.subtle.decrypt({...params,additionalData:ctx.chunkAad('other',0)},key,ciphertext));
 ciphertext[0]^=1;
 await assert.rejects(webcrypto.subtle.decrypt(params,key,ciphertext));
});
test('actual password derivation produces different wrapping keys for different passwords',async()=>{
 const salt=new Uint8Array(16),iv=new Uint8Array(12);
 const a=await ctx.derivePasswordWrappingKey('correct passphrase',salt,600000);
 const b=await ctx.derivePasswordWrappingKey('wrong passphrase',salt,600000);
 const encrypted=await webcrypto.subtle.encrypt({name:'AES-GCM',iv},a,new Uint8Array(32));
 await assert.rejects(webcrypto.subtle.decrypt({name:'AES-GCM',iv},b,encrypted));
});
