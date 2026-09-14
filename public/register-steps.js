const form=document.querySelector('#authForm'),tab=document.querySelector('#registerTab'),panel=document.querySelector('.auth-panel');
const groups=[['email'],['username','password'],['vaultPassword'],['code']];
let step=0,moving=false;
const motionReduced=matchMedia('(prefers-reduced-motion: reduce)');
const progress=document.createElement('p');progress.className='register-progress';progress.setAttribute('aria-live','polite');
const nav=document.createElement('div');nav.className='register-nav';
const back=document.createElement('button');back.type='button';back.className='register-back';back.textContent='←';back.setAttribute('aria-label','上一步');back.title='上一步';
const next=document.createElement('button');next.type='button';next.className='primary';next.textContent='下一步';
nav.append(next);panel.prepend(back);form.before(progress);form.append(nav);
const registering=()=>tab.classList.contains('active');
function render(focus=false){
 const active=registering();form.noValidate=active;panel.classList.toggle('register-stepped',active);panel.dataset.step=String(step);
 progress.hidden=nav.hidden=!active;back.hidden=!active||step===0;next.hidden=step===3;
 progress.textContent=['1 / 4 · 输入邮箱','2 / 4 · 设置登录信息','3 / 4 · 设置加密密码','4 / 4 · 验证邮箱'][step];
 if(active&&focus)form.elements[groups[step][0]].focus();
}
function validate(index){for(const name of groups[index]){const input=form.elements[name];if(!input.checkValidity()){step=index;render(true);input.reportValidity();return false;}}return true;}
async function move(target){
 if(moving||target===step)return;
 const direction=target>step?1:-1;
 if(motionReduced.matches){step=target;render(true);return;}
 moving=true;panel.inert=true;
 try{
  await panel.animate([{transform:'translateX(0)',opacity:1},{transform:`translateX(${-direction*64}px)`,opacity:0}],{duration:150,easing:'ease-in',fill:'forwards'}).finished;
  step=target;render();
  panel.getAnimations().forEach(a=>a.cancel());
  await panel.animate([{transform:`translateX(${direction*64}px)`,opacity:0},{transform:'translateX(0)',opacity:1}],{duration:220,easing:'cubic-bezier(.16,1,.3,1)'}).finished;
 }finally{panel.getAnimations().forEach(a=>a.cancel());panel.inert=false;moving=false;render(true);}
}
next.onclick=()=>{if(!moving&&validate(step))void move(step+1);};
back.onclick=()=>{if(!moving)void move(Math.max(0,step-1));};
form.addEventListener('submit',event=>{
 if(!registering())return;
 if(moving){event.preventDefault();event.stopImmediatePropagation();return;}
 if(step<3){event.preventDefault();event.stopImmediatePropagation();next.click();return;}
 for(let i=0;i<4;i++)if(!validate(i)){event.preventDefault();event.stopImmediatePropagation();return;}
},true);
new MutationObserver(()=>{step=0;render();}).observe(tab,{attributes:true,attributeFilter:['class']});
form.addEventListener('reset',()=>{step=0;render();});render();
