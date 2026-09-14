const params=new URLSearchParams(location.hash.slice(1));
let token=params.get('cancel-deletion')||new URLSearchParams(location.search).get('token')||'';
if(!/^[A-Za-z0-9_-]{32,128}$/.test(token)){location.replace('/');}
else {
history.replaceState(null,'','/recovery-account');
const restore=document.querySelector('#restore'),close=document.querySelector('#close'),status=document.querySelector('#status');
let ready=false,done=false,busy=false,signedOut=false;
Object.defineProperty(close,'disabled',{get(){return close.getAttribute('aria-disabled')==='true';},set(value){close.setAttribute('aria-disabled',String(value));}});
const valid=/^[A-Za-z0-9_-]{32,128}$/.test(token);
async function logout(){const r=await fetch('/api/logout',{method:'POST',credentials:'same-origin'});if(!r.ok)throw Error('安全退出未完成，请重试。');signedOut=true;}
async function initialize(){try{
 const response=await fetch('/api/account-deletion/validate',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
 if(response.status===404){
  token='';done=true;restore.hidden=true;
  document.querySelector('#title').textContent='此链接已使用或已过期';
  document.querySelector('#description').textContent='如果你已经恢复账户，可以返回首页自行登录，无需再次恢复。';
  document.querySelector('.hint').hidden=true;
  status.textContent='正在安全退出当前账户…';
  await logout();status.textContent='';close.disabled=false;close.textContent='返回登录';document.body.classList.add('verified');return;
 }
 if(!response.ok)throw Error('链接验证暂时失败，请重试。');
 await logout();ready=true;document.body.classList.add('verified');close.disabled=false;restore.disabled=false;status.textContent='';
}catch(e){document.body.classList.add('verification-error');status.textContent=e.message;close.disabled=false;close.textContent='返回首页';}}
restore.onclick=async()=>{
 if(!ready||busy)return;busy=true;restore.disabled=true;close.disabled=true;status.textContent='正在恢复账户…';
 try{const r=await fetch('/api/account-deletion/cancel',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const result=await r.json();if(!r.ok)throw Error(result.error||'恢复失败，请重试');
 token='';done=true;await logout();restore.hidden=true;document.querySelector('#title').textContent='账户已恢复';document.querySelector('#description').textContent='删除申请已撤销。请重新登录以继续使用。';status.textContent='';close.textContent='返回登录';
 }catch(e){status.textContent=e.message;restore.disabled=done;}finally{busy=false;close.disabled=false;}
};
close.onclick=async(event)=>{if(busy||close.disabled){event.preventDefault();return;}if(signedOut)return;event.preventDefault();close.disabled=true;restore.disabled=true;try{await logout();token='';location.replace('/');}catch(e){status.textContent=e.message;close.disabled=false;restore.disabled=!ready||done||!valid;}};
await initialize();
}
