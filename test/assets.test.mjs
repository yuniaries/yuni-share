import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
test('HTML script/style dependencies exist and SRI matches',()=>{
 const root=path.resolve('public');
 function inspect(dir){for(const item of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,item.name);if(item.isDirectory())inspect(file);else if(item.name.endsWith('.html')){
  for(const m of fs.readFileSync(file,'utf8').matchAll(/<(?:script|link)\b[^>]*>/g)){
   const tag=m[0],url=tag.match(/(?:src|href)=["'](\/[^"'?]+)(?:\?[^"']*)?["']/);
   if(!url||!(/\.(css|js)$/.test(url[1])))continue;
   const asset=path.join(root,url[1]);assert.ok(fs.existsSync(asset),`${file}: missing ${url[1]}`);
   const sri=tag.match(/integrity=["']([^"']+)["']/);if(sri)assert.equal(sri[1],'sha384-'+crypto.createHash('sha384').update(fs.readFileSync(asset)).digest('base64'),url[1]);
  }
 }}}
 inspect(root);
});
