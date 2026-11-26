/* NIQ Census MK – public web layer: access-code gate + Google Apps Script backed db/assets shims */
(function(){
const CFG=window.NIQ_CFG||{};
const $=id=>document.getElementById(id);
const PUB={name:'',code:''};window.PUB=PUB;

async function api(action,payload){
  const r=await fetch(CFG.api,{method:'POST',body:JSON.stringify({...payload,action,pw:PUB.code})});
  const j=await r.json();if(!j.ok){const e=new Error(j.error||'api_error');e.code=j.error;throw e}return j}
PUB.api=api;

/* ---------- decrypt store list with the access code ---------- */
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
let encP=null;const enc=()=>encP||(encP=fetch('stores.enc.json',{cache:'no-cache'}).then(r=>r.json()));
async function decrypt(code){const e=await enc();
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(code),'PBKDF2',false,['deriveKey']);
  const kdf=salt=>crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(salt),iterations:e.iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  let key;
  if(e.slots){let dek=null;for(const sl of e.slots){try{dek=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(sl.iv)},await kdf(sl.salt),b64(sl.wk));break}catch(x){}}
    if(!dek)throw new Error('bad_code');key=await crypto.subtle.importKey('raw',dek,'AES-GCM',false,['decrypt'])}
  else key=await kdf(e.salt);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(e.iv)},key,b64(e.ct));
  return JSON.parse(new TextDecoder().decode(pt))}

/* ---------- login gate ---------- */
let STORES=null;
function gate(){return new Promise(async resolve=>{
  const box=$('gate'),pw=$('gPw'),nm=$('gName'),btn=$('gGo'),msg=$('gMsg');
  let saved='';try{nm.value=localStorage.getItem('niqmk_name')||'';saved=localStorage.getItem('niqmk_code')||''}catch(e){}
  const tryCode=async c=>{try{STORES=await decrypt(c);PUB.code=c;return true}catch(e){return false}};
  if(saved&&nm.value){box.hidden=true;$('stat').textContent='Đang mở dữ liệu…';if(await tryCode(saved)){PUB.name=nm.value;return resolve()}}
  box.hidden=false;(nm.value?pw:nm).focus();
  const go=async()=>{const n=nm.value.trim(),c=pw.value.trim().toLowerCase();
    if(!n){msg.textContent='Nhập tên của bạn để ghi nhận ai đánh giá.';nm.focus();return}
    if(!c){msg.textContent='Nhập mã truy cập được cấp.';pw.focus();return}
    btn.disabled=true;msg.textContent='Đang mở dữ liệu…';
    if(!await tryCode(c)){btn.disabled=false;msg.textContent='Sai mã truy cập. Kiểm tra lại (dạng xxxx-xxxx-xxxx).';pw.select();return}
    try{localStorage.setItem('niqmk_name',n);localStorage.setItem('niqmk_code',c)}catch(e){}
    PUB.name=n;box.hidden=true;resolve()};
  btn.onclick=go;[pw,nm].forEach(i=>i.addEventListener('keydown',e=>{if(e.key==='Enter')go()}));
})}
PUB.logout=()=>{try{localStorage.removeItem('niqmk_name');localStorage.removeItem('niqmk_code')}catch(e){}location.reload()};
PUB.loadStores=async()=>STORES;

/* ---------- db shim: writes go to the Sheet, reads poll for changes ---------- */
const listeners={};let since=0,polling=false,pollT=null;
const docOf=(id,data)=>({id,data:()=>data});
async function poll(){if(polling)return;polling=true;
  try{const j=await api('list',{since});const by={};
    j.rows.forEach(r=>{if(r.at>since)since=r.at;(by[r.col]=by[r.col]||[]).push(r.del?{type:'removed',doc:docOf(r.id,{})}:{type:'modified',doc:docOf(r.id,r.data)})});
    Object.entries(by).forEach(([col,ch])=>(listeners[col]||[]).forEach(cb=>cb({docChanges:()=>ch})));
    Object.keys(listeners).forEach(col=>{if(!by[col]&&!PUB['_first_'+col]){PUB['_first_'+col]=1;listeners[col].forEach(cb=>cb({docChanges:()=>[]}))}});
    Object.keys(by).forEach(col=>PUB['_first_'+col]=1);
    PUB.online=true}
  catch(e){PUB.online=false;PUB.onErr&&PUB.onErr(e)}
  finally{polling=false;clearTimeout(pollT);pollT=setTimeout(poll,document.hidden?60000:15000)}}
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&PUB.code&&Object.keys(listeners).length){clearTimeout(pollT);poll()}});
PUB.db={collection(col){return{
  doc(id){return{
    async set(data){await api('set',{col,id,data})},
    async delete(){await api('del',{col,id})}}},
  onSnapshot(cb,err){(listeners[col]=listeners[col]||[]).push(cb);PUB.onErr=err;clearTimeout(pollT);pollT=setTimeout(poll,50);return()=>{}}}}};

/* ---------- assets shim: files go to a Drive folder ---------- */
const toB64=blob=>new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(String(r.result).split(',')[1]);r.onerror=rej;r.readAsDataURL(blob)});
const urlCache={};
PUB.assets={
  async upload(blob,opt){const mime=(opt&&opt.contentType)||blob.type||'application/octet-stream';
    const j=await api('upload',{mime,b64:await toB64(blob),name:'niqmk_'+Date.now()+'_'+(blob.name||'file')});
    urlCache[j.id]=URL.createObjectURL(blob);return{id:j.id,url:urlCache[j.id],contentType:mime}},
  async delete(id){await api('rmfile',{id})}};

/* media for <img data-blob> / <audio data-blob>, fetched through the backend (files stay private) */
let pend=new Set(),tm=null,busy=false;
async function flush(){tm=null;if(busy||!pend.size)return;busy=true;const ids=[...pend].slice(0,6);ids.forEach(i=>pend.delete(i));
  try{const j=await api('media',{ids});j.files.forEach(f=>{if(f.b64){const bin=b64(f.b64);urlCache[f.id]=URL.createObjectURL(new Blob([bin],{type:f.mime}))}else urlCache[f.id]='data:,'})}
  catch(e){ids.forEach(i=>urlCache[i]=urlCache[i]||'')}
  busy=false;apply(document);if(pend.size)tm=setTimeout(flush,30)}
function apply(root){root.querySelectorAll('[data-blob]').forEach(el=>{const id=el.dataset.blob;
  if(urlCache[id]!=null){if(urlCache[id]&&el.getAttribute('src')!==urlCache[id])el.src=urlCache[id]}else{pend.add(id);if(!tm)tm=setTimeout(flush,60)}})}
new MutationObserver(ms=>{for(const m of ms)for(const n of m.addedNodes)if(n.nodeType===1){if(n.matches&&n.matches('[data-blob]'))apply(n.parentNode||document);else if(n.querySelector&&n.querySelector('[data-blob]'))apply(n)}}).observe(document.documentElement,{childList:true,subtree:true});

/* ---------- user shim: "by" is the typed name ---------- */
PUB.user={id:async()=>PUB.name,can:async()=>true,profiles:async ids=>Object.fromEntries(ids.map(i=>[i,{name:i}]))};

/* ---------- in-browser audio recording ---------- */
let rec=null,chunks=[],tick=null,t0=0;
PUB.record=(btn,done)=>{
  if(!(navigator.mediaDevices&&window.MediaRecorder))return false;
  if(rec){rec.stop();return true}
  navigator.mediaDevices.getUserMedia({audio:true}).then(stream=>{
    const mt=['audio/mp4','audio/webm;codecs=opus','audio/webm'].find(t=>MediaRecorder.isTypeSupported&&MediaRecorder.isTypeSupported(t))||'';
    rec=new MediaRecorder(stream,mt?{mimeType:mt}:{});chunks=[];t0=Date.now();
    rec.ondataavailable=e=>{if(e.data&&e.data.size)chunks.push(e.data)};
    rec.onstop=()=>{clearInterval(tick);stream.getTracks().forEach(t=>t.stop());const type=(rec.mimeType||mt||'audio/webm').split(';')[0];
      const f=new File(chunks,'ghi-am.'+(/mp4/.test(type)?'m4a':'webm'),{type});rec=null;
      document.querySelectorAll('[data-rec]').forEach(b=>b.textContent='🎙 Ghi âm');done(f)};
    rec.start(1000);
    const upd=()=>{const s=Math.round((Date.now()-t0)/1000);document.querySelectorAll('[data-rec]').forEach(b=>b.textContent='⏹ Dừng ghi '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0'))};upd();tick=setInterval(upd,1000);
  }).catch(()=>{const i=document.getElementById('audIn');i.value='';i.click()});
  return true};

PUB.ready=gate();
})();
