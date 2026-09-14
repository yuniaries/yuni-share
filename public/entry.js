const action=new URLSearchParams(location.hash.slice(1));
if(action.has('cancel-deletion')){
 location.replace('/recovery-account#cancel-deletion='+encodeURIComponent(action.get('cancel-deletion')||''));
}else{
 window.addEventListener('hashchange',event=>{
  const params=new URLSearchParams(location.hash.slice(1));
  if(params.has('cancel-deletion')){event.stopImmediatePropagation();document.body.replaceChildren();location.replace('/recovery-account#cancel-deletion='+encodeURIComponent(params.get('cancel-deletion')||''));}
 });
 await import('/app.js?v=20260909-username-r1');
}
