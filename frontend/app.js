// ─── constants & state ────────────────────────────────────────────────────────
const AV = ['av-0','av-1','av-2','av-3','av-4','av-5'];

const S = {
  vaults: [], tokens: {}, activeVault: null, unlockVaultId: null,
  pendingUnlockPw: '', entries: [], categories: [], filtered: [],
  cat: 'all', q: '', selectedId: null, editId: null, fromEntry: false, sortBy: 'name-az',
  genPw: '', twofaSecret: '', totpIntervals: [], addCatColor: '#8b5cf6', addVaultShared: false, addVaultMode: 'create',
  autolock: 1800, lockAt: 0, lockWarningShown: false, lockInterval: null,
  pinData: {},  // {vaultId: {enc,iv,salt}} - session only
  pendingWebAuthnOpts: null,
  activityLog: [],
  _lastMtime: {},          // {vaultId: mtime} for shared vault polling
  _mtimeInterval: null,
};

function avChar(t){ return (t||'?')[0].toUpperCase(); }
function avCls(t){ return AV[((t||'').charCodeAt(0)||0) % AV.length]; }
function strColor(s){ return s>=80?'#10b981':s>=55?'#fbbf24':s>=30?'#fb923c':'#f43f5e'; }
function getToken(vid){ return S.tokens[vid||S.activeVault]||null; }
function catLabel(id){ const c=S.categories.find(x=>x.id===id); return c?c.label:(id||'Other'); }
function catColor(id){ const c=S.categories.find(x=>x.id===id); return c?(c.color||'#64748b'):'#64748b'; }
function catIcon(id){ const c=S.categories.find(x=>x.id===id); return c?(c.icon||'\uD83D\uDCC1'):'\uD83D\uDCC1'; }

// ─── API wrapper ──────────────────────────────────────────────────────────────
const api = {
  async req(method,path,body,tok){
    const headers={'Content-Type':'application/json'};
    const t=tok!==undefined?tok:getToken();
    if(t) headers['X-Session-Token']=t;
    const opts={method,headers};
    if(body) opts.body=JSON.stringify(body);
    const r=await fetch(path,opts);
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||'Request failed');
    return data;
  },
  vaults(){ return this.req('GET','/api/vaults',null,null); },
  addVault(d){ return this.req('POST','/api/vaults',d,null); },
  updateVault(id,d){ return this.req('PUT',`/api/vaults/${id}`,d,null); },
  deleteVault(id){ return this.req('DELETE',`/api/vaults/${id}`,null,null); },
  vaultUnlock(id,pw,code){
    const b={password:pw};
    if(code) b.totp_code=code;
    return this.req('POST',`/api/vaults/${id}/unlock`,b,null);
  },
  vaultCreate(id,pw){ return this.req('POST',`/api/vaults/${id}/create`,{password:pw},null); },
  vaultLock(id){ return this.req('POST',`/api/vaults/${id}/lock`,{},getToken(id)); },
  vaultSetPath(id,path){ return this.req('PUT',`/api/vaults/${id}/path`,{path},null); },
  twoFAStatus(id){ return this.req('GET',`/api/vaults/${id}/2fa/status`,null,null); },
  twoFASetup(id){ return this.req('POST',`/api/vaults/${id}/2fa/setup`,{},getToken(id)); },
  twoFAEnable(id,secret,code){ return this.req('POST',`/api/vaults/${id}/2fa/enable`,{secret,code},getToken(id)); },
  twoFADisable(id){ return this.req('POST',`/api/vaults/${id}/2fa/disable`,{},getToken(id)); },
  backupCodes(id){ return this.req('POST',`/api/vaults/${id}/2fa/backup-codes`,{},getToken(id)); },
  backupCodesStatus(id){ return this.req('GET',`/api/vaults/${id}/2fa/backup-codes/status`,null,getToken(id)); },
  emailTwoFASetup(id,email){ return this.req('POST',`/api/vaults/${id}/2fa/email/setup`,{email},getToken(id)); },
  emailTwoFAStatus(id){ return this.req('GET',`/api/vaults/${id}/2fa/email/status`,null,getToken(id)); },
  emailTwoFADisable(id){ return this.req('POST',`/api/vaults/${id}/2fa/email/disable`,{},getToken(id)); },
  smtpGet(){ return this.req('GET','/api/smtp',null,null); },
  smtpSet(d){ return this.req('POST','/api/smtp',d,null); },
  smtpTest(to){ return this.req('POST','/api/smtp/test',{to},null); },
  importEntries(entries){ return this.req('POST','/api/import',{entries}); },
  entries(tok){ return this.req('GET','/api/entries',null,tok); },
  add(d){ return this.req('POST','/api/entries',d); },
  update(id,d){ return this.req('PUT',`/api/entries/${id}`,d); },
  del(id){ return this.req('DELETE',`/api/entries/${id}`); },
  categories(){ return this.req('GET','/api/categories',null,getToken()); },
  addCategory(d){ return this.req('POST','/api/categories',d); },
  deleteCategory(id){ return this.req('DELETE',`/api/categories/${id}`); },
  health(){ return this.req('GET','/api/health',null,getToken()); },
  setAutolock(s){ return this.req('POST','/api/settings/autolock',{seconds:s}); },
  generate(opts){ return this.req('POST','/api/generate',opts,null); },
  strength(pw){ return this.req('POST','/api/strength',{password:pw},null); },
  sessionTouch(){ return this.req('POST','/api/session/touch',{}); },
  listFiles(){       return this.req('GET','/api/files',null,getToken()); },
  deleteFile(id){    return this.req('DELETE',`/api/files/${id}`,null,getToken()); },
  renameFile(id,nm){ return this.req('PUT',`/api/files/${id}`,{name:nm},getToken()); },
  ping(){            return fetch('/api/ping',{method:'POST'}).catch(()=>{}); },
  quit(){            return this.req('POST','/api/quit',null,null); },
  vaultActivity(id){ return this.req('GET',`/api/vaults/${id}/activity`,null,getToken(id)); },
  vaultMtime(id){ return this.req('GET',`/api/vaults/${id}/mtime`,null,null); },
  vaultMerge(id,src_id,src_pw){ return this.req('POST',`/api/vaults/${id}/merge`,{source_vault_id:src_id,source_password:src_pw},getToken(id)); },
  webauthnStatus(id){ return this.req('GET',`/api/vaults/${id}/2fa/webauthn/status`,null,null); },
  webauthnRegisterBegin(id){ return this.req('POST',`/api/vaults/${id}/2fa/webauthn/register-begin`,{},getToken(id)); },
  webauthnRegisterFinish(id,d){ return this.req('POST',`/api/vaults/${id}/2fa/webauthn/register-finish`,d,getToken(id)); },
  webauthnDisable(id){ return this.req('POST',`/api/vaults/${id}/2fa/webauthn/disable`,{}); },
  changePw(pw){ return this.req('POST','/api/change-password',{new_password:pw}); },
};

// ─── toast / modal ────────────────────────────────────────────────────────────
function toast(msg,type){
  type=type||'info';
  const tc=document.getElementById('toast-container');
  const t=document.createElement('div');
  t.className='toast '+type; t.textContent=msg; tc.appendChild(t);
  requestAnimationFrame(()=>requestAnimationFrame(()=>t.classList.add('show')));
  setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),300);},2800);
}
function openModal(id){ document.getElementById(id).classList.add('open'); }
function closeModal(id){ document.getElementById(id).classList.remove('open'); }
document.addEventListener('keydown',ev=>{
  if(ev.key==='Escape'){
    document.querySelectorAll('.modal-overlay.open').forEach(m=>m.classList.remove('open'));
    closeDetail();
  }
  // Ctrl+C with no text selected → copy password of active entry
  if(ev.key==='c'&&(ev.ctrlKey||ev.metaKey)&&!ev.shiftKey){
    const sel=window.getSelection();
    if(sel&&sel.toString().length>0) return; // let normal copy happen
    if(S.selectedId){
      const e=S.entries.find(x=>x.id===S.selectedId);
      if(e&&e.password){ ev.preventDefault(); copyField(e.password,'Password'); }
    }
  }
  // Ctrl+, → open settings
  if(ev.key===','&&(ev.ctrlKey||ev.metaKey)){ ev.preventDefault(); openSettings(); }
  // Ctrl+L → lock vault
  if(ev.key==='l'&&(ev.ctrlKey||ev.metaKey)&&S.activeVault){ ev.preventDefault(); lockVault(S.activeVault); }
  // Ctrl+N → new entry
  if(ev.key==='n'&&(ev.ctrlKey||ev.metaKey)&&S.activeVault){ ev.preventDefault(); openAddEntry(); }
  // / or Ctrl+F → focus search
  if((ev.key==='/'||(ev.key==='f'&&(ev.ctrlKey||ev.metaKey)))&&S.activeVault){
    const sf=document.getElementById('search-input');
    if(sf&&document.activeElement!==sf){ ev.preventDefault(); sf.focus(); }
  }
});
function togglePwVis(btn,inputId){
  const inp=document.getElementById(inputId);
  if(inp.type==='password'){inp.type='text';btn.innerHTML='&#128064;';}
  else{inp.type='password';btn.innerHTML='&#128065;';}
}
async function copyField(val,label){
  if(!val){toast('Nothing to copy','info');return;}
  try{
    await navigator.clipboard.writeText(val);
    toast((label||'Value')+' copied — clears in 30s ⏱','success');
    if(window._clipTimer) clearTimeout(window._clipTimer);
    window._clipTimer=setTimeout(()=>navigator.clipboard.writeText('').catch(()=>{}),30000);
  } catch(e){toast('Copy failed','error');}
}
function showSettingsTab(paneId,btn){
  document.querySelectorAll('#settings-modal .tab-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('#settings-modal .tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(paneId).classList.add('active');
  btn.classList.add('active');
}

// ─── vault unlock screen ──────────────────────────────────────────────────────
function showUnlockScreen(vaultId){
  S.unlockVaultId=vaultId||(S.vaults[0]||{}).id||null;
  document.getElementById('app').style.display='none';
  document.getElementById('unlock-screen').style.display='flex';
  renderVaultTabs();
  // Zero-vault state: hide form, show add-vault prompt
  const form=document.getElementById('unlock-form');
  const notice2=document.getElementById('unlock-novault-notice');
  if(!S.vaults.length){
    if(form) form.style.display='none';
    if(notice2) notice2.style.display='block';
    return;
  } else {
    if(notice2) notice2.style.display='none';
    if(form) form.style.display='block';
  }
  const vault=S.vaults.find(v=>v.id===S.unlockVaultId)||{};
  const notice=document.getElementById('shared-path-notice');
  const totp=document.getElementById('totp-form');
  if(totp) totp.style.display='none';
  if(S.unlockVaultId==='shared'&&!vault.path){
    notice.style.display='block'; form.style.display='none';
  } else {
    notice.style.display='none'; form.style.display='block';
  }
  const btn=document.getElementById('unlock-btn');
  if(btn) btn.textContent=vault.exists?'Unlock Vault':'Create Vault';
  const pw=document.getElementById('unlock-pw');
  if(pw) pw.value='';
  const err=document.getElementById('unlock-error');
  if(err) err.textContent='';
  // Show 'Forgot password?' only for existing vaults with email 2FA
  const forgotLink=document.getElementById('forgot-pw-link');
  if(forgotLink) forgotLink.style.display=(vault.has_email2fa && vault.exists)?'block':'none';
  // Show PIN option if we have a session pin for this vault
  const pinForm=document.getElementById('pin-unlock-form');
  const hasPinSession=vault.exists && !!S.pinData[S.unlockVaultId];
  if(pinForm && hasPinSession){
    form.style.display='none';
    pinForm.style.display='block';
    const pinEl=document.getElementById('pin-unlock-input');
    if(pinEl){pinEl.value='';setTimeout(()=>pinEl.focus(),100);}
  } else if(pinForm){
    pinForm.style.display='none';
  }
}

function renderVaultTabs(){
  const tabs=document.getElementById('vault-tabs');
  if(!tabs) return;
  tabs.innerHTML='';
  if(!S.vaults.length) return;  // no vaults - unlock screen handles empty state
  if(true){  // always compact dropdown
    // Compact dropdown for many vaults
    const sel=document.createElement('select');
    sel.className='vault-dropdown';
    sel.setAttribute('aria-label','Select vault');
    S.vaults.forEach(v=>{
      const opt=document.createElement('option');
      opt.value=v.id;
      const unlocked=!!S.tokens[v.id];
      opt.textContent=v.label+' ['+(unlocked?'Unlocked':'Locked')+']';
      if(v.id===S.unlockVaultId) opt.selected=true;
      sel.appendChild(opt);
    });
    sel.onchange=(e)=>{
      const v=S.vaults.find(x=>x.id===e.target.value);
      if(!v) return;
      !!S.tokens[v.id]?switchVault(v.id):showUnlockScreen(v.id);
    };
    const editRow=document.createElement('div');
    editRow.style.cssText='display:flex;justify-content:flex-end;margin-top:4px';
    const editBtn=document.createElement('button');
    editBtn.style.cssText='font-size:11px;color:var(--text-3);padding:3px 8px;border:1px solid var(--border);border-radius:6px;background:var(--surface2);cursor:pointer';
    editBtn.textContent='Edit Vault';
    editBtn.onmouseover=()=>editBtn.style.color='var(--accent)';
    editBtn.onmouseout=()=>editBtn.style.color='var(--text-3)';
    editBtn.onclick=()=>{const v=S.vaults.find(x=>x.id===S.unlockVaultId);if(v) openVaultEditModal(v.id);};
    editRow.appendChild(editBtn);
    tabs.appendChild(sel);
    tabs.appendChild(editRow);
  } else {
    S.vaults.forEach(v=>{
      const btn=document.createElement('button');
      btn.className='vault-tab'+(v.id===S.unlockVaultId?' active':'');
      const unlocked=!!S.tokens[v.id];
      // Avatar
      const av=document.createElement('div');
      av.className='vault-tab-avatar '+avCls(v.label);
      av.textContent=avChar(v.label);
      // Info
      const info=document.createElement('div'); info.className='vault-tab-info';
      const nm=document.createElement('div'); nm.className='vault-tab-name'; nm.textContent=v.label;
      const mt=document.createElement('div'); mt.className='vault-tab-meta';
      mt.textContent=v.shared?'Shared vault':'Local vault';
      info.appendChild(nm); info.appendChild(mt);
      // Status badge
      const st=document.createElement('span');
      st.className='vault-tab-status '+(unlocked?'unlocked':'locked');
      st.textContent=unlocked?'Unlocked':'Locked';
      btn.appendChild(av); btn.appendChild(info); btn.appendChild(st);
      btn.onclick=(e)=>{if(e.target.closest('.vault-tab-edit-btn')) return; unlocked?switchVault(v.id):showUnlockScreen(v.id);};
      // Edit icon
      const editBtn=document.createElement('button');
      editBtn.className='vault-tab-edit-btn'; editBtn.title='Edit vault';
      editBtn.innerHTML='&#9881;';
      editBtn.onclick=(e)=>{e.stopPropagation();openVaultEditModal(v.id);};
      btn.appendChild(editBtn);
      tabs.appendChild(btn);
    });
  }
  // Auto-enter if vault is already unlocked and is the only one
  if(S.vaults.length===1 && S.tokens[S.vaults[0].id]){
    switchVault(S.vaults[0].id);
  }
}

function openAddVaultFromHome(){openAddVaultModal(false);}

function openVaultEditModal(vaultId){
  const v=S.vaults.find(x=>x.id===vaultId); if(!v) return;
  document.getElementById('vault-edit-id').value=v.id;
  document.getElementById('vault-edit-name').value=v.label;
  document.getElementById('vault-edit-title').textContent='Edit: '+v.label;
  const pr=document.getElementById('vault-edit-path-row');
  if(pr) pr.style.display=v.shared?'block':'none';
  const pe=document.getElementById('vault-edit-path'); if(pe) pe.value=v.path||'';
  const delBtn=document.getElementById('vault-edit-del-btn');
  if(delBtn) delBtn.style.display='';
  document.getElementById('vault-edit-error').textContent='';
  const pwEl=document.getElementById('vault-edit-pw'); if(pwEl) pwEl.value='';
  // Show 2FA field if vault has authenticator 2FA enabled
  const edit2faRow=document.getElementById('vault-edit-2fa-row');
  const edit2faCode=document.getElementById('vault-edit-2fa-code');
  if(edit2faRow) edit2faRow.style.display=v.has_2fa?'':'none';
  if(edit2faCode) edit2faCode.value='';
  openModal('vault-edit-modal');
  setTimeout(()=>document.getElementById('vault-edit-name').focus(),100);
}

async function doUpdateVaultEdit(){
  const id=document.getElementById('vault-edit-id').value;
  const label=(document.getElementById('vault-edit-name').value||'').trim();
  const password=(document.getElementById('vault-edit-pw').value||'').trim();
  const errEl=document.getElementById('vault-edit-error');
  if(!label){errEl.textContent='Name required';return;}
  if(!password){errEl.textContent='Enter the vault password to save changes';return;}
  // 2FA check for vault with TOTP
  const twoFACode=document.getElementById('vault-edit-2fa-code');
  const vault=S.vaults.find(v=>v.id===id);
  if(vault&&vault.has_2fa&&(!twoFACode||!twoFACode.value.trim())){
    errEl.textContent='Enter your authenticator code to authorise this change';
    if(twoFACode){twoFACode.closest('.form-row').style.display='';twoFACode.focus();}
    return;
  }
  const pe=document.getElementById('vault-edit-path');
  const path=pe?pe.value.trim():null;
  try{
    const twoFAEl=document.getElementById('vault-edit-2fa-code');
    const twofa_code=twoFAEl?twoFAEl.value.trim():'';
    await api.updateVault(id,{label,path,password,totp_code:twofa_code});
    const vd=await api.vaults(); S.vaults=vd.vaults;
    closeModal('vault-edit-modal');
    renderVaultTabs(); renderVaultSwitcher();
    toast('Vault updated','success');
  } catch(e){errEl.textContent=e.message;}
}

function confirmDeleteVaultFromEdit(){
  const id=document.getElementById('vault-edit-id').value;
  const v=S.vaults.find(x=>x.id===id); if(!v) return;
  closeModal('vault-edit-modal');
  confirmDeleteVault(id,v.label);
}

function renderVaultSwitcher(){
  const sw=document.getElementById('vault-switcher');
  if(!sw) return;
  sw.innerHTML='';
  S.vaults.forEach(v=>{
    const unlocked=!!S.tokens[v.id];
    const item=document.createElement('div');
    item.className='vault-switch-item'+(v.id===S.activeVault?' active':'');
    const icon=document.createElement('span');
    icon.className='vault-switch-icon';
    icon.textContent=unlocked?'\uD83D\uDD13':'\uD83D\uDD12';
    const lbl=document.createElement('span');
    lbl.className='vault-switch-label'; lbl.textContent=v.label;
    item.appendChild(icon); item.appendChild(lbl);
    item.onclick=unlocked?()=>switchVault(v.id):()=>showUnlockScreen(v.id);
    sw.appendChild(item);
  });
}

// ─── unlock & 2FA flow ────────────────────────────────────────────────────────
async function doUnlock(){
  const pw=(document.getElementById('unlock-pw').value||'').trim();
  if(!pw){toast('Enter your master password','error');return;}
  const vault=S.vaults.find(v=>v.id===S.unlockVaultId);
  if(!vault){toast('No vault selected','error');return;}
  const errEl=document.getElementById('unlock-error');
  if(errEl) errEl.textContent='';
  try{
    let res;
    if(vault.exists){
      res=await api.vaultUnlock(vault.id,pw);
      if(res.needs_webauthn){
        S.pendingUnlockPw=pw;
        S.pendingWebAuthnOpts=res;
        document.getElementById('unlock-form').style.display='none';
        const wf=document.getElementById('webauthn-form');
        if(wf) wf.style.display='block';
        return;
      }
      if(res.needs_2fa){
        S.pendingUnlockPw=pw;
        document.getElementById('unlock-form').style.display='none';
        const tf=document.getElementById('totp-form');
        if(tf) tf.style.display='block';
        const tc=document.getElementById('totp-code');
        if(tc){tc.value='';setTimeout(()=>tc.focus(),100);}
        return;
      }
      toast('Vault unlocked','success');
    } else {
      if(pw.length<8){toast('Password must be at least 8 characters','error');return;}
      res=await api.vaultCreate(vault.id,pw);
      toast('Vault created!','success');
    }
    S.tokens[vault.id]=res.token;
    storePinSession(vault.id, pw);
    const vd=await api.vaults(); S.vaults=vd.vaults;
    switchVault(vault.id);
  } catch(err){
    if(errEl) errEl.textContent=err.message;
    else toast(err.message,'error');
  }
}

async function doTOTPVerify(){
  const code=(document.getElementById('totp-code').value||'').trim();
  if(!code||code.length<6){toast('Enter the 6-digit code','error');return;}
  const vault=S.vaults.find(v=>v.id===S.unlockVaultId);
  if(!vault) return;
  const errEl=document.getElementById('totp-error');
  if(errEl) errEl.textContent='';
  try{
    const res=await api.vaultUnlock(vault.id,S.pendingUnlockPw,code);
    S.tokens[vault.id]=res.token; S.pendingUnlockPw='';
    const vd=await api.vaults(); S.vaults=vd.vaults;
    toast('Vault unlocked','success');
    switchVault(vault.id);
  } catch(err){
    if(errEl) errEl.textContent=err.message;
    const tc=document.getElementById('totp-code');
    if(tc){tc.value='';tc.focus();}
  }
}

function cancelTOTP(){
  S.pendingUnlockPw='';
  document.getElementById('totp-form').style.display='none';
  document.getElementById('unlock-form').style.display='block';
  const e=document.getElementById('totp-error'); if(e) e.textContent='';
}

async function quitApp(){
  if(!confirm('Close Secure Vault? The server process will exit.')) return;
  try { await api.quit(); } catch(e) {}
  setTimeout(()=>window.close(), 300);
}
async function doLock(){
  const vid=S.activeVault; if(!vid) return;
  try{
    await api.vaultLock(vid); delete S.tokens[vid];
    delete S.pinData[vid];  // clear PIN on manual lock
    stopLockCountdown();
    const vd=await api.vaults(); S.vaults=vd.vaults;
    const other=S.vaults.find(v=>S.tokens[v.id]);
    if(other){switchVault(other.id);toast('Vault locked','info');}
    else{S.activeVault=null;showUnlockScreen(vid);toast('Vault locked','info');}
  } catch(err){toast(err.message,'error');}
}

async function switchVault(vaultId){
  S.activeVault=vaultId; S.cat='all'; S.q=''; S.selectedId=null;
  startLockCountdown(S.autolock);
  closeDetail(); clearTotpIntervals();
  const qEl=document.getElementById('search-input'); if(qEl) qEl.value='';
  const avl=document.getElementById('active-vault-label');
  const vault=S.vaults.find(v=>v.id===vaultId)||{};
  if(avl) avl.textContent=vault.label||'Vault';
  renderVaultSwitcher();
  document.getElementById('unlock-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  await loadCategories();
  await loadEntries();
  await initVaultMtime(vaultId);
  startSharedVaultPolling();
}

// ─── categories ───────────────────────────────────────────────────────────────
async function loadCategories(){
  try{
    const d=await api.categories(); S.categories=d.categories||[];
    renderCatNav(); populateCatSelect();
  } catch(e){}
}

function renderCatNav(){
  const nav=document.getElementById('cat-nav'); if(!nav) return;
  // keep static items (All, Favorites) - only clear dynamic cats
  const dynamics=nav.querySelectorAll('.dynamic-cat');
  dynamics.forEach(d=>d.remove());
  S.categories.forEach(cat=>{
    const item=document.createElement('div');
    item.className='nav-item dynamic-cat'+(S.cat===cat.id?' active':'');
    item.dataset.cat=cat.id;
    item.onclick=(e)=>{if(e.target.closest('.cat-item-actions')) return; setCat(item);};
    const icon=document.createElement('span'); icon.className='nav-icon'; icon.textContent=cat.icon||'\uD83D\uDCC1';
    const labelWrap=document.createElement('div'); labelWrap.className='cat-item-wrap';
    const lbl=document.createElement('span'); lbl.className='cat-item-label'; lbl.textContent=cat.label;
    const cnt=document.createElement('span'); cnt.className='nav-count'; cnt.id='count-'+cat.id;
    cnt.textContent=S.entries.filter(e=>e.category===cat.id).length;
    const acts=document.createElement('div'); acts.className='cat-item-actions';
    const editBtn=document.createElement('button'); editBtn.className='cat-action-btn'; editBtn.innerHTML='&#9998;'; editBtn.title='Rename';
    editBtn.onclick=(e)=>{e.stopPropagation();startInlineCatRename(item,cat,lbl);};
    const delBtn=document.createElement('button'); delBtn.className='cat-action-btn del'; delBtn.innerHTML='&#10005;'; delBtn.title='Delete';
    delBtn.onclick=(e)=>{e.stopPropagation();
      dangerConfirm({
        title:'Remove Category',
        name:cat.label,
        desc:'Entries in this category will move to Other.',
        btnLabel:'Remove',
        action:async()=>{
          try{await api.deleteCategory(cat.id);await loadCategories();renderCatNav();toast('Category removed','info');}
          catch(err){toast(err.message,'error');}
        }
      });
    };
    acts.appendChild(editBtn); acts.appendChild(delBtn);
    labelWrap.appendChild(lbl); labelWrap.appendChild(cnt); labelWrap.appendChild(acts);
    item.appendChild(icon); item.appendChild(labelWrap);
    nav.appendChild(item);
  });
}

function startInlineCatRename(item, cat, lblSpan){
  const inp=document.createElement('input');
  inp.className='cat-inline-input'; inp.value=cat.label; inp.maxLength=30;
  lblSpan.replaceWith(inp); inp.focus(); inp.select();
  async function save(){
    const newLabel=inp.value.trim();
    if(newLabel && newLabel!==cat.label){
      try{await api.updateCategory(cat.id,{label:newLabel});await loadCategories();renderCatNav();}
      catch(e){toast(e.message,'error');renderCatNav();}
    } else { renderCatNav(); }
  }
  inp.addEventListener('blur',save);
  inp.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();inp.blur();}if(e.key==='Escape'){inp.removeEventListener('blur',save);renderCatNav();}});
}


function populateCatSelect(){
  const sel=document.getElementById('f-cat'); if(!sel) return;
  const cur=sel.value; sel.innerHTML='';
  S.categories.forEach(cat=>{
    const opt=document.createElement('option');
    opt.value=cat.id; opt.textContent=cat.label; sel.appendChild(opt);
  });
  if(cur&&sel.querySelector(`option[value="${cur}"]`)) sel.value=cur;
}


// ── multi-category chip picker ────────────────────────────────────────────────
function renderCatChips(selectedIds){
  const wrap = document.getElementById('cat-chips'); if(!wrap) return;
  wrap.innerHTML = '';
  S.categories.forEach(cat => {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'cat-chip' + (selectedIds.includes(cat.id) ? ' selected' : '');
    chip.dataset.id = cat.id;
    chip.textContent = (cat.icon || '') + ' ' + cat.label;
    if(selectedIds.includes(cat.id)){
      chip.style.background = cat.color || '#8b5cf6';
      chip.style.borderColor = cat.color || '#8b5cf6';
      chip.style.color = '#fff';
    }
    chip.onclick = () => {
      chip.classList.toggle('selected');
      const sel = chip.classList.contains('selected');
      chip.style.background = sel ? (cat.color||'#8b5cf6') : '';
      chip.style.borderColor = sel ? (cat.color||'#8b5cf6') : '';
      chip.style.color = sel ? '#fff' : '';
    };
    wrap.appendChild(chip);
  });
}
function getSelectedCats(){
  const chips = document.querySelectorAll('#cat-chips .cat-chip.selected');
  const ids = Array.from(chips).map(c => c.dataset.id);
  return ids.length ? ids : ['other'];
}

// ── quick-add category from entry modal ────────────────────────────────────────
let _qcatColor = '#8b5cf6';
function openQuickAddCat(){
  const form = document.getElementById('quick-cat-form'); if(!form) return;
  form.style.display = 'block';
  document.getElementById('qcat-name').value = '';
  document.getElementById('qcat-icon').value = '';
  document.getElementById('qcat-color').value = '#8b5cf6'; _qcatColor = '#8b5cf6';
  document.querySelectorAll('#qcat-colors .color-dot').forEach((d,i)=>d.style.borderColor=i===0?'white':'transparent');
  setTimeout(()=>document.getElementById('qcat-name').focus(),50);
}
function closeQuickAddCat(){
  const form = document.getElementById('quick-cat-form'); if(form) form.style.display='none';
}
function selectQCatColor(el, color){
  document.querySelectorAll('#qcat-colors .color-dot').forEach(d=>d.style.borderColor='transparent');
  el.style.borderColor='white'; _qcatColor=color;
}
async function doQuickAddCat(){
  const name=(document.getElementById('qcat-name').value||'').trim();
  if(!name){toast('Enter a category name','error');return;}
  const icon=(document.getElementById('qcat-icon').value||'').trim()||'\uD83D\uDCC1';
  try{
    const cat = await api.addCategory({label:name, icon, color:_qcatColor});
    await loadCategories();
    closeQuickAddCat();
    // re-render chips keeping existing selections, auto-select the new one
    const existing = getSelectedCats();
    renderCatChips([...existing, cat.id]);
    toast('Category added','success');
  } catch(e){toast(e.message,'error');}
}

function sortEntries(list, by){
  const copy = [...list];
  if(by === 'name-az') return copy.sort((a,b)=>(a.title||'').localeCompare(b.title||''));
  if(by === 'name-za') return copy.sort((a,b)=>(b.title||'').localeCompare(a.title||''));
  if(by === 'newest')  return copy.sort((a,b)=>(b.created_at||0)-(a.created_at||0));
  if(by === 'oldest')  return copy.sort((a,b)=>(a.created_at||0)-(b.created_at||0));
  if(by === 'strength')return copy.sort((a,b)=>(b.strength_score||0)-(a.strength_score||0));
  if(by === 'expiry')  return copy.sort((a,b)=>{
    if(!a.expiry_date && !b.expiry_date) return 0;
    if(!a.expiry_date) return 1; if(!b.expiry_date) return -1;
    return a.expiry_date.localeCompare(b.expiry_date);
  });
  if(by === 'modified') return copy.sort((a,b)=>(b.updated_at||0)-(a.updated_at||0));
  return copy;
}
function setSortBy(val){ S.sortBy=val; applyFilter(); }

function toggleTheme(){
  const light = document.body.classList.toggle('light-mode');
  localStorage.setItem('theme', light ? 'light' : 'dark');
  const btn = document.getElementById('theme-toggle-btn');
  if(btn) btn.textContent = light ? '\u263D' : '\u2600';
}
function applyStoredTheme(){
  const t = localStorage.getItem('theme') || 'dark';
  if(t === 'light'){
    document.body.classList.add('light-mode');
    const btn = document.getElementById('theme-toggle-btn');
    if(btn) btn.textContent = '\u263D';
  }
}
function initAppearance(){ initAppearance(); loadAccentColor(); }


function duplicateEntry(id){
  const e = S.entries.find(x=>x.id===id); if(!e) return;
  S.editId = null;
  document.getElementById('modal-title').textContent = 'Add Entry';
  document.getElementById('f-title').value = 'Copy of ' + (e.title||'');
  document.getElementById('f-username').value = e.username||'';
  document.getElementById('f-password').value = e.password||'';
  document.getElementById('f-url').value = e.url||'';
  document.getElementById('f-notes').value = e.notes||'';
  const ft=document.getElementById('f-totp'); if(ft) ft.value='';
  const fe=document.getElementById('f-expiry'); if(fe) fe.value='';
  document.getElementById('f-fav').checked = false;
  const cats = e.categories && e.categories.length ? e.categories : (e.category ? [e.category] : ['other']);
  renderCatChips(cats);
  checkStr(e.password||'');
  openModal('entry-modal');
  setTimeout(()=>document.getElementById('f-title').focus(),100);
}

function doExport(fmt){
  const a = document.createElement('a');
  const tok = getToken();
  a.href = '/api/export?format=' + fmt;
  // Fetch with auth header then trigger download
  fetch('/api/export?format=' + fmt, {headers: tok ? {'X-Session-Token': tok} : {}})
    .then(r => {
      if(!r.ok) throw new Error('Export failed');
      const disp = r.headers.get('Content-Disposition') || '';
      const fname = disp.match(/filename=([^;]+)/)?.[1] || ('export.' + fmt);
      return r.blob().then(b => ({b, fname}));
    })
    .then(({b, fname}) => {
      const url = URL.createObjectURL(b);
      const a2 = document.createElement('a'); a2.href = url; a2.download = fname;
      document.body.appendChild(a2); a2.click();
      setTimeout(()=>{URL.revokeObjectURL(url); a2.remove();}, 1000);
      toast('Exported ' + fname, 'success');
    })
    .catch(e => toast(e.message, 'error'));
}

let _importData = [];
function openImportModal(){
  _importData = [];
  document.getElementById('import-file').value = '';
  document.getElementById('import-preview').style.display = 'none';
  document.getElementById('import-status').textContent = '';
  document.getElementById('import-confirm-btn').style.display = 'none';
  document.getElementById('import-parse-btn').style.display = '';
  closeModal('settings-modal');
  openModal('import-modal');
}
function parseImportFile(){
  const fi = document.getElementById('import-file');
  const fmt = document.getElementById('import-format').value;
  if(!fi.files || !fi.files[0]){ toast('Choose a file first','error'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    try{
      _importData = parseImportData(e.target.result, fi.files[0].name, fmt);
      const prev = document.getElementById('import-preview');
      const lbl = document.getElementById('import-preview-label');
      const tbl = document.getElementById('import-preview-table');
      lbl.textContent = _importData.length + ' entries found. Preview (first 5):';
      tbl.innerHTML = '';
      _importData.slice(0,5).forEach(row=>{
        const d = document.createElement('div');
        d.style.cssText = 'border-bottom:1px solid var(--border);padding:4px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis';
        d.textContent = (row.title||'?') + ' — ' + (row.username||'') + ' — ' + (row.url||'');
        tbl.appendChild(d);
      });
      prev.style.display = 'block';
      document.getElementById('import-confirm-btn').style.display = '';
      document.getElementById('import-status').textContent = '';
    } catch(ex){
      document.getElementById('import-status').textContent = 'Parse error: ' + ex.message;
    }
  };
  reader.readAsText(fi.files[0]);
}
function parseImportData(text, filename, fmt){
  const ext = filename.split('.').pop().toLowerCase();
  const detectedFmt = fmt === 'auto' ? (ext === 'json' ? 'bitwarden' : 'csv') : fmt;
  if(detectedFmt === 'bitwarden'){
    const data = JSON.parse(text);
    const items = data.items || data.entries || (Array.isArray(data) ? data : []);
    return items.map(i=>({
      title: i.name || i.title || '',
      username: (i.login && i.login.username) || i.username || '',
      password: (i.login && i.login.password) || i.password || '',
      url: (i.login && i.login.uris && i.login.uris[0] && i.login.uris[0].uri) || i.url || '',
      notes: i.notes || '',
      category: i.type === 1 ? 'login' : (i.type === 3 ? 'work' : 'other'),
      favorite: !!(i.favorite),
    }));
  }
  // CSV parsing
  const lines = text.split(/\r?\n/).filter(l=>l.trim());
  if(!lines.length) return [];
  const headers = lines[0].split(',').map(h=>h.replace(/^"|"$/g,'').trim().toLowerCase());
  const isLastPass = headers.includes('grouping') || headers.includes('extra');
  return lines.slice(1).map(line=>{
    const cols = splitCsvLine(line);
    const get = (...keys) => { for(const k of keys){ const i=headers.indexOf(k); if(i>=0&&cols[i]) return cols[i].replace(/^"|"$/g,'').trim(); } return ''; };
    return {
      title: get('title','name','site name'),
      username: get('username','login_username','user name','email'),
      password: get('password','login_password'),
      url: get('url','login_uri','website'),
      notes: get('notes','extra','comment'),
      category: get('category','grouping','type') || 'other',
      favorite: get('favorite','starred') === '1',
    };
  }).filter(e=>e.title||e.url);
}
function splitCsvLine(line){
  const result=[]; let cur=''; let inQ=false;
  for(let i=0;i<line.length;i++){
    if(line[i]==='"') inQ=!inQ;
    else if(line[i]===',' && !inQ){result.push(cur);cur='';}
    else cur+=line[i];
  }
  result.push(cur); return result;
}
async function confirmImport(){
  if(!_importData.length){toast('Nothing to import','error');return;}
  const btn=document.getElementById('import-confirm-btn');
  btn.textContent='Importing...'; btn.disabled=true;
  try{
    const r=await api.importEntries(_importData);
    closeModal('import-modal'); openModal('settings-modal');
    await loadEntries();
    toast('Imported ' + r.imported + ' entries','success');
  }catch(e){toast(e.message,'error');}
  finally{btn.textContent='Import';btn.disabled=false;}
}

async function selectTwofaEmailSetup(){
  const vid = S._2faVaultId || S.activeVault;
  try{
    const smtp = await api.smtpGet();
    if(!smtp.host){
      // Close twofa-setup-modal first so smtp-modal (earlier in DOM) is visible
      closeModal('twofa-setup-modal');
      openSmtpModal(
        ()=>{ openModal('twofa-setup-modal'); selectTwofaEmailSetup(); },
        ()=>{ openModal('twofa-setup-modal'); } // cancel: reopen at type picker
      );
      return;
    }
  }catch(e){ toast(e.message,'error'); return; }
  // SMTP confirmed - now hide picker and show email form
  document.getElementById('twofa-type-picker').style.display='none';
  document.getElementById('twofa-email-setup').style.display='';
  document.getElementById('twofa-email-err').textContent='';
  const footer=document.getElementById('twofa-modal-footer');
  if(footer) footer.innerHTML=
    '<button class="btn-secondary" onclick="open2FASetup(S._2faVaultId)">Back</button>'+
    '<button class="btn-save" onclick="doEnableEmailTwoFA()">Enable</button>';
  setTimeout(()=>document.getElementById('twofa-email-addr').focus(),150);
}
async function doEnableEmailTwoFA(){
  const vid = S._2faVaultId || S.activeVault;
  const email = (document.getElementById('twofa-email-addr').value||'').trim();
  const err = document.getElementById('twofa-email-err');
  if(!email || !email.includes('@')){err.textContent='Enter a valid email address';return;}
  const btn = document.querySelector('#twofa-modal-footer .btn-save');
  if(btn){btn.textContent='Saving...';btn.disabled=true;}
  try{
    await api.emailTwoFASetup(vid, email);
    closeModal('twofa-setup-modal'); openModal('settings-modal');
    render2FAStatus(S.activeVault);
    toast('Email 2FA enabled. Code will be emailed on each unlock.','success');
  }catch(e){
    err.textContent = e.message;
    if(btn){btn.textContent='Enable';btn.disabled=false;}
  }
}
// SMTP settings
async function loadSmtpSettings(){
  try{
    const d = await api.smtpGet();
    document.getElementById('smtp-host').value = d.host||'';
    document.getElementById('smtp-port').value = d.port||587;
    document.getElementById('smtp-user').value = d.username||'';
    document.getElementById('smtp-pass').value = d.password||'';
    // Update the configured status label
    const lbl = document.getElementById('smtp-configured-label');
    if(lbl) lbl.textContent = d.host ? ('Configured: '+d.username) : 'Not configured';
  }catch(e){}
}
function openSmtpModal(callback, cancelCallback){
  S._smtpCallback = callback||null;
  S._smtpCancelCallback = cancelCallback||null;
  loadSmtpSettings();
  document.getElementById('smtp-status').textContent='';
  openModal('smtp-modal');
}
function closeSmtpModal(){
  const cancel = S._smtpCancelCallback;
  S._smtpCallback = null;
  S._smtpCancelCallback = null;
  closeModal('smtp-modal');
  if(cancel) cancel();
}
function openSmtpFromWizard(){
  // Close addvault modal first so smtp-modal (earlier in DOM) is visible
  closeModal('addvault-modal');
  openSmtpModal(()=>{
    openModal('addvault-modal');
    doAddVaultSelectMethod('email');
  });
}
function applySmtpPreset(p){
  const presets = {
    gmail:   {host:'smtp.gmail.com',   port:587},
    outlook: {host:'smtp.office365.com',port:587},
    yahoo:   {host:'smtp.mail.yahoo.com',port:587},
  };
  if(presets[p]){
    document.getElementById('smtp-host').value = presets[p].host;
    document.getElementById('smtp-port').value = presets[p].port;
  }
}
async function saveSmtp(){
  const d={
    host:   document.getElementById('smtp-host').value.trim(),
    port:   parseInt(document.getElementById('smtp-port').value)||587,
    username: document.getElementById('smtp-user').value.trim(),
    from_addr: document.getElementById('smtp-user').value.trim(),
    password: document.getElementById('smtp-pass').value,
  };
  const st=document.getElementById('smtp-status');
  const btn=document.querySelector('#smtp-modal .btn-save');
  if(btn){btn.textContent='Saving...';btn.disabled=true;}
  try{
    await api.smtpSet(d);
    st.style.color='var(--green)'; st.textContent='SMTP saved';
    if(btn){btn.textContent='Save';btn.disabled=false;}
    const lbl=document.getElementById('smtp-configured-label');
    if(lbl) lbl.textContent = d.host ? ('Configured: '+d.username) : 'Not configured';
    // Fire callback if set (e.g. proceeding to email OTP after configuring SMTP)
    if(S._smtpCallback){
      const fn=S._smtpCallback; S._smtpCallback=null;
      closeModal('smtp-modal'); await fn();
    }
  }
  catch(e){
    st.style.color='var(--red)'; st.textContent=e.message;
    if(btn){btn.textContent='Save';btn.disabled=false;}
  }
}
async function testSmtp(){
  const to = document.getElementById('smtp-user').value.trim() || prompt('Send test to:');
  if(!to) return;
  const st=document.getElementById('smtp-status');
  st.style.color='var(--text-2)'; st.textContent='Sending...';
  try{
    await api.smtpTest(to);
    st.style.color='var(--green)'; st.textContent='Test email sent to ' + to;
  }catch(e){ st.style.color='var(--red)'; st.textContent='Failed: '+e.message; }
}
// ─── entries ──────────────────────────────────────────────────────────────────
function pwStrength(pw){
  if(!pw) return {score:0,label:'Empty'};
  const hasL=/[a-z]/.test(pw),hasU=/[A-Z]/.test(pw),hasD=/[0-9]/.test(pw),hasS=/[^a-zA-Z0-9]/.test(pw);
  const sets=[hasL,hasU,hasD,hasS].filter(Boolean).length;
  let pool=0;
  if(hasL)pool+=26; if(hasU)pool+=26; if(hasD)pool+=10; if(hasS)pool+=32;
  const entropy=pool>0?pw.length*Math.log2(pool):0;
  let score=Math.min(Math.round(entropy*1.8),100);
  score=Math.max(score,Math.min(25*sets,100));
  if(pw.length<8)score=Math.min(score,20); else if(pw.length<12)score=Math.min(score,55);
  const label=score<=19?'Very Weak':score<=39?'Weak':score<=59?'Fair':score<=79?'Strong':'Very Strong';
  return {score,label};
}

function strColor(score){
  if(score<=19)return'var(--red)'; if(score<=39)return'var(--red)';
  if(score<=59)return'var(--yellow)'; if(score<=79)return'var(--green)';
  return'var(--cyan)';
}

async function loadEntries(){
  const tok=getToken(); if(!tok) return;
  clearTotpIntervals();
  try{
    const d=await api.entries(tok);
    S.entries=(d.entries||[]).map(e=>({...e,strength_score:pwStrength(e.password||'').score}));
    updateCounts(); applyFilter();
  } catch(err){toast('Failed to load entries: '+err.message,'error');}
}
function clearTotpIntervals(){ S.totpIntervals.forEach(id=>clearInterval(id)); S.totpIntervals=[]; }

function applyFilter(){
  let list=S.entries;
  if(S.cat==='favorites') list=list.filter(e=>e.favorite);
  else if(S.cat!=='all') list=list.filter(e=>(e.categories&&e.categories.length?e.categories:[e.category]).includes(S.cat));
  if(S.q){
    const q=S.q.toLowerCase();
    list=list.filter(e=>
      (e.title||'').toLowerCase().includes(q)||(e.username||'').toLowerCase().includes(q)||
      (e.url||'').toLowerCase().includes(q)||(e.notes||'').toLowerCase().includes(q));
  }
  // Sort
  list = sortEntries(list, S.sortBy);
  S.filtered=list; updateSub(); renderEntries();
}

function updateSub(){
  const n=S.filtered.length;
  document.getElementById('cat-sub').textContent=n+' '+(n===1?'entry':'entries');
  document.getElementById('cat-title').textContent=
    S.cat==='all'?'All Items':S.cat==='favorites'?'Favorites':catLabel(S.cat);
}

function renderEntries(){
  const grid=document.getElementById('entries-grid'); grid.innerHTML='';
  if(!S.filtered.length){
    const d=document.createElement('div'); d.className='empty-state';
    const ic=document.createElement('div'); ic.className='empty-icon'; ic.textContent='\uD83D\uDD13';
    const h=document.createElement('h3'); h.textContent=S.q?'No results found':'No entries yet';
    const p=document.createElement('p'); p.textContent=S.q?'Try a different search term.':'Click \u201c+ Add Entry\u201d to get started.';
    d.appendChild(ic); d.appendChild(h); d.appendChild(p); grid.appendChild(d); return;
  }
  S.filtered.forEach(e=>{
    const card=document.createElement('div');
    card.className='entry-card'+(e.id===S.selectedId?' selected':'');
    card.onclick=()=>selectEntry(e.id);
    const hdr=document.createElement('div'); hdr.className='entry-card-header';
    const av=document.createElement('div'); av.className='entry-avatar '+avCls(e.title); av.textContent=avChar(e.title);
    const info=document.createElement('div'); info.className='entry-card-info';
    const te=document.createElement('div'); te.className='entry-title'; te.textContent=e.title;
    const ue=document.createElement('div'); ue.className='entry-username'; ue.textContent=e.username||'';
    info.appendChild(te); info.appendChild(ue);
    const acts=document.createElement('div'); acts.className='entry-card-actions';
    const eb=document.createElement('button'); eb.className='entry-action-btn'; eb.title='Edit';
    eb.innerHTML='&#9999;&#65039;'; eb.onclick=ev=>{ev.stopPropagation();openEditEntry(e.id);};
    const cpb2=document.createElement('button'); cpb2.className='entry-action-btn'; cpb2.title='Duplicate';
    cpb2.innerHTML='&#128203;'; cpb2.onclick=ev=>{ev.stopPropagation();duplicateEntry(e.id);};
    const db=document.createElement('button'); db.className='entry-action-btn del'; db.title='Delete';
    db.innerHTML='&#128465;&#65039;'; db.onclick=ev=>{ev.stopPropagation();confirmDelete(e.id,e.title);};
    acts.appendChild(eb); acts.appendChild(cpb2); acts.appendChild(db);
    hdr.appendChild(av); hdr.appendChild(info); hdr.appendChild(acts); card.appendChild(hdr);
    // ── file entry ──
    if(e.entry_type==='file'){
      card.classList.add('file-entry');
      card.onclick=null;
      // Fix action buttons: edit opens file editor, hide duplicate
      const [editBtn,dupBtn]=card.querySelectorAll('.entry-card-actions .entry-action-btn');
      if(editBtn) editBtn.onclick=ev=>{ev.stopPropagation();openFileEdit(e.id);};
      if(dupBtn)  dupBtn.style.display='none';
      const av2=card.querySelector('.entry-avatar');
      if(av2) av2.textContent=fileIcon(e.file_mime||'');
      const sz=document.createElement('div'); sz.className='file-size-badge';
      sz.textContent=fmtSize(e.file_size||0);
      card.appendChild(sz);
      const ftr2=document.createElement('div'); ftr2.className='entry-footer';
      const clr2=catColor(e.category);
      const badge2=document.createElement('span'); badge2.className='entry-category-badge';
      badge2.style.background=clr2+'22'; badge2.style.color=clr2; badge2.textContent=catLabel(e.category);
      const fav2=document.createElement('span'); fav2.className='fav-star'+(e.favorite?' active':''); fav2.textContent='★';
      const dlb=document.createElement('button'); dlb.className='copy-pw-btn download-btn'; dlb.textContent='↓ Download';
      dlb.onclick=ev=>{ev.stopPropagation();downloadFile(e.id,e.title);};
      ftr2.appendChild(badge2); ftr2.appendChild(fav2); ftr2.appendChild(dlb);
      card.appendChild(ftr2); grid.appendChild(card);
      return;
    }

    if(e.url){const ul=document.createElement('div');ul.className='entry-url';ul.textContent=e.url;card.appendChild(ul);}
    const ftr=document.createElement('div'); ftr.className='entry-footer';
    const clr=catColor(e.category);
    const badge=document.createElement('span'); badge.className='entry-category-badge';
    badge.style.background=clr+'22'; badge.style.color=clr; badge.textContent=catLabel(e.category);
    const fav=document.createElement('span'); fav.className='fav-star'+(e.favorite?' active':''); fav.textContent='\u2605';
    if(e.expiry_date){
      const exp=document.createElement('span');
      const days=Math.ceil((new Date(e.expiry_date)-new Date())/(1000*86400));
      exp.className=days<0?'expiry-expired':days<=30?'expiry-warn':'expiry-ok';
      exp.textContent=days<0?'Expired':(days===0?'Expires today':('Exp '+days+'d'));
      ftr.appendChild(exp);
    }
    // strength dot
    const sdot=document.createElement('span'); sdot.className='str-dot';
    sdot.style.background=strColor(e.strength_score||0);
    sdot.title=(e.strength_score||0)+'% — '+(pwStrength(e.password||'').label);
    // copy buttons
    const cpb=document.createElement('button'); cpb.className='copy-pw-btn'; cpb.textContent='Copy PW';
    cpb.onclick=ev=>{ev.stopPropagation();copyField(e.password,'Password');};
    const cub=document.createElement('button'); cub.className='copy-pw-btn'; cub.textContent='Copy UN';
    cub.onclick=ev=>{ev.stopPropagation();copyField(e.username||'','Username');};
    cub.style.display=e.username?'':'none';
    ftr.appendChild(badge); ftr.appendChild(fav); ftr.appendChild(sdot); ftr.appendChild(cub); ftr.appendChild(cpb);
    if(e.totp&&e.totp.code){
      const tb=document.createElement('span'); tb.className='totp-badge'; tb.title='Click to copy';
      tb.textContent='\uD83D\uDD11 '+e.totp.code;
      tb.onclick=ev=>{ev.stopPropagation();copyField(e.totp.code,'TOTP code');};
      ftr.appendChild(tb);
    }
    card.appendChild(ftr); grid.appendChild(card);
  });
}

// ─── detail panel ─────────────────────────────────────────────────────────────
function selectEntry(id){
  S.selectedId=id; const e=S.entries.find(x=>x.id===id); if(!e) return;
  renderEntries(); renderDetail(e);
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('detail-title').textContent=e.title;
}
function closeDetail(){
  S.selectedId=null;
  const dp=document.getElementById('detail-panel'); if(dp) dp.classList.remove('open');
}

function renderDetail(e){
  const body=document.getElementById('detail-body'); body.innerHTML='';
  function addField(label,value,mono,canCopy,secret){
    if(!value&&!secret) return;
    const row=document.createElement('div'); row.className='detail-field';
    const lbl=document.createElement('label'); lbl.textContent=label;
    const wrap=document.createElement('div'); wrap.className='detail-value';
    const span=document.createElement('span'); span.className=mono?'mono':'plain';
    if(secret){span.textContent='\u2022'.repeat(8);span.dataset.v=value;span.dataset.h='1';}
    else{span.textContent=value||'';}
    wrap.appendChild(span);
    if(canCopy){
      const cb=document.createElement('button'); cb.className='copy-btn';
      cb.innerHTML='&#128203;'; cb.title='Copy';
      cb.onclick=()=>copyField(secret?span.dataset.v:span.textContent,label);
      wrap.appendChild(cb);
    }
    if(label==='Password'&&secret){
      const breachRow=document.createElement('div'); breachRow.className='breach-row';
      const breachBtn=document.createElement('button'); breachBtn.className='breach-btn';
      breachBtn.textContent='\uD83D\uDD0D Check breach';
      const breachResult=document.createElement('span');
      breachBtn.onclick=()=>checkBreach(span.dataset.v,breachResult,breachBtn);
      breachRow.appendChild(breachBtn); breachRow.appendChild(breachResult);
      // append after wrap — use a wrapper
      row.appendChild(lbl); row.appendChild(wrap); row.appendChild(breachRow);
      body.appendChild(row); return; // skip default append
    }
    if(secret){
      const sb=document.createElement('button'); sb.className='show-btn';
      sb.innerHTML='&#128065;'; sb.title='Reveal';
      sb.onclick=()=>{
        if(span.dataset.h==='1'){span.textContent=span.dataset.v;span.dataset.h='0';sb.innerHTML='&#128064;';}
        else{span.textContent='\u2022'.repeat(8);span.dataset.h='1';sb.innerHTML='&#128065;';}
      };
      wrap.appendChild(sb);
    }
    row.appendChild(lbl); row.appendChild(wrap); body.appendChild(row);
  }
  if(e.username) addField('Username',e.username,false,true,false);
  if(e.password) addField('Password',e.password,true,true,true);
  if(e.url){
    // URL with open button
    const urow=document.createElement('div'); urow.className='detail-field';
    const ulbl=document.createElement('label'); ulbl.textContent='URL';
    const uwrap=document.createElement('div'); uwrap.className='detail-value';
    const uspan=document.createElement('span'); uspan.className='plain'; uspan.textContent=e.url;
    const ucpy=document.createElement('button'); ucpy.className='copy-btn'; ucpy.innerHTML='&#128203;'; ucpy.title='Copy';
    ucpy.onclick=()=>copyField(e.url,'URL');
    const uopen=document.createElement('button'); uopen.className='copy-btn'; uopen.innerHTML='&#127758;'; uopen.title='Open in browser';
    uopen.onclick=()=>openEntryUrl(e.url);
    uwrap.appendChild(uspan); uwrap.appendChild(ucpy); uwrap.appendChild(uopen);
    urow.appendChild(ulbl); urow.appendChild(uwrap); body.appendChild(urow);
  }
  if(e.totp_secret){
    const row=document.createElement('div'); row.className='detail-field';
    const lbl=document.createElement('label'); lbl.textContent='TOTP Code';
    const live=document.createElement('div'); live.className='totp-live';
    const codeEl=document.createElement('span'); codeEl.className='totp-code';
    codeEl.textContent=e.totp?e.totp.code:'------';
    const timerEl=document.createElement('span'); timerEl.className='totp-timer-text';
    timerEl.textContent=e.totp?(e.totp.remaining+'s'):'';
    const cpb=document.createElement('button'); cpb.className='totp-copy-btn';
    cpb.innerHTML='&#128203;'; cpb.title='Copy';
    cpb.onclick=()=>copyField(codeEl.textContent,'TOTP code');
    live.appendChild(codeEl); live.appendChild(timerEl); live.appendChild(cpb);
    row.appendChild(lbl); row.appendChild(live); body.appendChild(row);
    const secret=e.totp_secret;
    const iv=setInterval(async()=>{
      try{
        const r=await fetch('/api/totp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret})});
        const d=await r.json();
        if(codeEl.parentNode){codeEl.textContent=d.code||'------';timerEl.textContent=(d.remaining||0)+'s';}
      }catch(ex){}
    },1000);
    S.totpIntervals.push(iv);
  }
  if(e.expiry_date){
    const row=document.createElement('div'); row.className='detail-field';
    const lbl=document.createElement('label'); lbl.textContent='Password Expires';
    const days=Math.ceil((new Date(e.expiry_date)-new Date())/(1000*86400));
    const cls=days<0?'expiry-expired':days<=30?'expiry-warn':'expiry-ok';
    const val=document.createElement('span'); val.className=cls;
    const d=new Date(e.expiry_date).toLocaleDateString();
    val.textContent=d+(days<0?' (Expired)':(days<=30?' (Soon)':''));
    row.appendChild(lbl); row.appendChild(val); body.appendChild(row);
  }
  if(e.notes){
    const row=document.createElement('div'); row.className='detail-field';
    const lbl=document.createElement('label'); lbl.textContent='Notes';
    const nd=document.createElement('div'); nd.className='detail-notes'; nd.textContent=e.notes;
    row.appendChild(lbl); row.appendChild(nd); body.appendChild(row);
  }
  // Password history
  if(e.password_history && e.password_history.length){
    const histRow=document.createElement('div'); histRow.className='detail-field';
    const histLbl=document.createElement('label'); histLbl.textContent='Password History';
    const histWrap=document.createElement('div');
    histWrap.style.cssText='display:flex;flex-direction:column;gap:4px;width:100%';
    const toggle=document.createElement('button');
    toggle.className='btn-secondary'; toggle.style.cssText='font-size:11px;padding:3px 8px;width:fit-content';
    toggle.textContent='Show '+e.password_history.length+' previous password'+(e.password_history.length>1?'s':'');
    const histList=document.createElement('div'); histList.style.display='none';
    e.password_history.forEach((pw,i)=>{
      const item=document.createElement('div');
      item.style.cssText='display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid var(--border)';
      const num=document.createElement('span'); num.style.cssText='font-size:11px;color:var(--text-3);min-width:16px'; num.textContent=(i+1)+'.';
      const pspan=document.createElement('span'); pspan.className='mono'; pspan.style.cssText='font-size:12px;flex:1;color:var(--text-2)';
      pspan.textContent='•'.repeat(Math.min(pw.length,12));
      pspan.dataset.v=pw;
      const cpy=document.createElement('button'); cpy.className='copy-btn'; cpy.innerHTML='&#128203;'; cpy.title='Copy';
      cpy.onclick=()=>copyField(pw,'Old password');
      const rev=document.createElement('button'); rev.className='show-btn'; rev.innerHTML='&#128065;'; rev.title='Reveal';
      rev.onclick=()=>{ if(pspan.textContent.includes('•')){pspan.textContent=pw;rev.innerHTML='&#128064;';}else{pspan.textContent='•'.repeat(Math.min(pw.length,12));rev.innerHTML='&#128065;';} };
      item.append(num,pspan,cpy,rev); histList.appendChild(item);
    });
    toggle.onclick=()=>{
      const shown=histList.style.display!=='none';
      histList.style.display=shown?'none':'block';
      toggle.textContent=(shown?'Show':'Hide')+' '+e.password_history.length+' previous password'+(e.password_history.length>1?'s':'');
    };
    histWrap.appendChild(toggle); histWrap.appendChild(histList);
    histRow.appendChild(histLbl); histRow.appendChild(histWrap); body.appendChild(histRow);
  }

  const allCats = e.categories && e.categories.length ? e.categories : (e.category ? [e.category] : ['other']);
  const catRow=document.createElement('div'); catRow.className='detail-field';
  const catLbl=document.createElement('label'); catLbl.textContent='Categories';
  const catWrap=document.createElement('div'); catWrap.style.cssText='display:flex;flex-wrap:wrap;gap:4px';
  allCats.forEach(cid=>{
    const clr=catColor(cid);
    const badge=document.createElement('span'); badge.className='entry-category-badge';
    badge.style.background=clr+'22'; badge.style.color=clr; badge.textContent=catLabel(cid);
    catWrap.appendChild(badge);
  });
  catRow.appendChild(catLbl); catRow.appendChild(catWrap); body.appendChild(catRow);
}

function editSel(){ if(S.selectedId) openEditEntry(S.selectedId); }
function dupSel(){ if(S.selectedId) duplicateEntry(S.selectedId); }
function deleteSel(){ if(S.selectedId){ const e=S.entries.find(x=>x.id===S.selectedId); if(e) confirmDelete(e.id,e.title); } }

// ─── add/edit entry ───────────────────────────────────────────────────────────


function openEditEntry(id){
  const e=S.entries.find(x=>x.id===id); if(!e) return;
  if(e.entry_type==='file'){ openFileEdit(id); return; }
  S.editId=id;
  document.getElementById('modal-title').textContent='Edit Entry';
  document.getElementById('f-title').value=e.title||'';
  document.getElementById('f-username').value=e.username||'';
  document.getElementById('f-password').value=e.password||'';
  document.getElementById('f-url').value=e.url||'';
  document.getElementById('f-notes').value=e.notes||'';
  const ft=document.getElementById('f-totp'); if(ft) ft.value=e.totp_secret||'';
  const fe=document.getElementById('f-expiry'); if(fe) fe.value=e.expiry_date||'';
  const eCats = e.categories && e.categories.length ? e.categories : (e.category ? [e.category] : ['other']);
  renderCatChips(eCats);
  document.getElementById('f-fav').checked=!!e.favorite;
  checkStr(e.password||''); openModal('entry-modal');
}

async function saveEntry(){
  const title=document.getElementById('f-title').value.trim();
  if(!title){toast('Title is required','error');return;}
  const ft=document.getElementById('f-totp');
  const entryTypeEl=document.getElementById('f-entry-type');
  const data={
    title, username:document.getElementById('f-username').value,
    password:document.getElementById('f-password').value,
    url:document.getElementById('f-url').value,
    entry_type:entryTypeEl?entryTypeEl.value:'login',
    category:getSelectedCats()[0]||'other',
    categories:getSelectedCats(),
    notes:document.getElementById('f-notes').value,
    favorite:document.getElementById('f-fav').checked,
    expiry_date:document.getElementById('f-expiry')?document.getElementById('f-expiry').value:'',
    totp_secret:ft?ft.value.trim().replace(/\s/g,''):'',
  };
  try{
    if(S.editId){await api.update(S.editId,data);toast('Entry updated','success');}
    else{await api.add(data);toast('Entry added','success');}
    closeModal('entry-modal');
    await loadEntries();
    if(S.editId){const u=S.entries.find(x=>x.id===S.editId);if(u){S.selectedId=u.id;renderDetail(u);}}
  } catch(err){toast(err.message,'error');}
}

function confirmDelete(id,title){
  dangerConfirm({
    title: 'Delete Entry',
    name: title,
    desc: 'This entry will be permanently deleted.',
    btnLabel: 'Delete',
    action: async () => { await doDelete(id); }
  });
}
async function doDelete(id){
  try{
    await api.del(id);
    if(S.selectedId===id) closeDetail();
    await loadEntries(); toast('Entry deleted','success');
  } catch(err){toast(err.message,'error');}
}

// ─── password strength / generator ───────────────────────────────────────────
async function checkStr(pw){
  if(!pw){document.getElementById('str-bar').style.width='0';document.getElementById('str-label').textContent='';return;}
  try{
    const s=await api.strength(pw);
    document.getElementById('str-bar').style.width=s.score+'%';
    document.getElementById('str-bar').style.background=strColor(s.score);
    document.getElementById('str-label').textContent=s.label;
  }catch(e){}
}
function openGenerator(fromEntry){ S.fromEntry=!!fromEntry; openModal('gen-modal'); genPw(); }
function fillGenPw(){ openGenerator(true); }
async function genPw(){
  try{
    const len=parseInt(document.getElementById('gen-len').value)||16;
    const res=await api.generate({length:len,upper:document.getElementById('gen-upper').checked,digits:document.getElementById('gen-digits').checked,symbols:document.getElementById('gen-symbols').checked,no_ambiguous:document.getElementById('gen-no-amb').checked});
    S.genPw=res.password; document.getElementById('gen-output').textContent=res.password;
    const s=res.strength;
    document.getElementById('gen-str-bar').style.width=s.score+'%';
    document.getElementById('gen-str-bar').style.background=strColor(s.score);
    document.getElementById('gen-str-label').textContent=s.label;
  }catch(e){}
}
// ─── passphrase generator ────────────────────────────────────────────────────
const PWORDS = ['able','acid','aged','also','apex','arch','army','aura','away','baby',
  'back','bake','ball','band','bank','bare','barn','base','bath','beam','bean','bear',
  'beat','bell','belt','best','bike','bill','bind','bird','bite','blue','blur','boat',
  'bold','bolt','bond','bone','book','boom','born','boss','both','bowl','brag','brew',
  'brow','bulk','burn','busy','buzz','cage','cake','calm','camp','cape','card','care',
  'cart','case','cave','chef','chip','chop','city','clap','clay','clip','club','clue',
  'coal','coat','code','coil','cold','come','cone','cool','cope','copy','core','corn',
  'cost','cozy','crab','crew','crop','curl','cute','damp','dare','dark','dart','dash',
  'data','date','dawn','days','deep','deny','desk','diet','dirt','disk','dock','dome',
  'done','door','dots','dove','down','draw','drip','drop','drum','dual','dusk','dust',
  'each','earn','east','edge','epic','even','ever','evil','exam','face','fact','fade',
  'fair','fame','farm','fast','fate','fear','feel','feet','fell','felt','file','fill',
  'film','find','fire','firm','fish','flag','flat','flew','flip','flow','foam','fold',
  'folk','font','food','foot','ford','fork','form','fort','foul','free','from','fuel',
  'full','fund','fuse','gaze','gear','gift','give','glad','glow','glue','goal','gold',
  'golf','good','gown','grab','gray','grew','grid','grin','grip','grow','gulf','guru',
  'gust','half','hall','halt','hand','hang','hard','harm','harp','hash','haul','have',
  'hawk','haze','head','heal','heap','heat','heel','held','helm','help','herb','here',
  'high','hike','hill','hint','hold','hole','holy','home','hope','horn','host','hour',
  'huge','hull','hunt','hurt','hype','icon','idea','idle','inch','into','iris','iron',
  'isle','item','jade','jail','jazz','join','joke','jump','just','keen','keep','kind',
  'king','knit','knob','know','lack','lake','lamp','land','lane','lark','last','late',
  'lazy','lead','leaf','lean','leap','left','lend','lens','lift','like','lime','line',
  'link','lion','list','live','load','lock','loft','logo','lone','long','look','loop',
  'lore','loss','loud','love','luck','lull','lure','lurk','made','mail','main','make',
  'malt','many','mark','mart','mask','mast','math','maze','meal','mean','meet','mend',
  'menu','mere','mesh','mile','milk','mill','mind','mint','miss','mist','mode','mood',
  'moon','more','most','move','much','mull','muse','must','mute','nail','name','navy',
  'neat','need','nest','news','next','nice','node','none','norm','nose','note','nova',
  'oath','obey','once','open','oval','over','pace','pack','page','pain','palm','park',
  'part','pass','path','pave','peak','peel','peer','pine','pipe','plan','play','plea',
  'plum','plus','poem','pole','pool','port','pose','post','pour','pray','prey','prim',
  'prod','prop','pull','pure','push','quiz','race','rack','rage','raid','rain','rake',
  'ramp','rank','rare','rate','read','real','reap','reed','reef','reel','rely','rent',
  'rest','rice','rich','ride','ring','riot','risk','road','roam','roar','robe','rock',
  'rode','role','roll','roof','room','root','rope','rose','rout','rule','rune','rush',
  'rust','safe','saga','sail','sake','salt','same','sand','sane','sang','save','scan',
  'seal','seam','seek','self','sell','send','shed','ship','shop','shot','show','shut',
  'side','sigh','silk','sing','sink','site','size','skin','skip','slab','slap','slim',
  'slip','slow','snap','soft','soil','sold','sole','some','song','soon','sort','soul',
  'span','spin','spit','spot','spur','star','stay','stem','step','stir','stop','strap',
  'stub','stud','such','suit','sung','surf','swan','swap','sway','swim','take','tale',
  'tall','tame','tang','tank','task','team','tear','tech','tell','term','test','text',
  'than','that','them','then','thus','tide','tile','time','tiny','tire','toil','toll',
  'tone','tool','tops','torn','tour','town','tree','trim','trio','trip','true','tube',
  'tuck','tuft','tune','turf','turn','twin','type','unit','used','vale','vast','very',
  'view','vine','void','volt','vote','wade','wake','walk','wall','wand','warm','warn',
  'wary','wave','ways','week','well','went','west','what','when','wide','wild','will',
  'wind','wine','wing','wire','wise','wish','with','wolf','wood','word','work','worn',
  'wrap','wren','yard','year','yoga','your','zeal','zero','zinc','zone','zoom'];

function genPassphrase(){
  const n=parseInt(document.getElementById('pp-count')?.value||'5');
  const disp=document.getElementById('pp-count-disp'); if(disp) disp.textContent=n;
  const sep=document.getElementById('pp-sep')?.value||'-';
  const cap=document.getElementById('pp-cap')?.checked||false;
  const arr=new Uint32Array(n);
  crypto.getRandomValues(arr);
  const words=Array.from(arr).map(v=>{
    const w=PWORDS[v%PWORDS.length];
    return cap?w[0].toUpperCase()+w.slice(1):w;
  });
  S.genPw=words.join(sep);
  const out=document.getElementById('gen-output');
  if(out) out.textContent=S.genPw;
  // show entropy
  const bits=Math.round(n*Math.log2(PWORDS.length));
  const lbl=document.getElementById('gen-str-label');
  if(lbl) lbl.textContent='~'+bits+' bits of entropy';
  const bar=document.getElementById('gen-str-bar');
  if(bar){ const pct=Math.min(bits*1.2,100); bar.style.width=pct+'%'; bar.style.background=pct>70?'var(--green)':pct>45?'var(--yellow)':'var(--red)'; }
}

function switchGenTab(tab){
  document.getElementById('gen-tab-pw').classList.toggle('active', tab==='pw');
  document.getElementById('gen-tab-pp').classList.toggle('active', tab==='pp');
  document.getElementById('gen-pw-body').style.display = tab==='pw'?'':'none';
  document.getElementById('gen-pp-body').style.display = tab==='pp'?'':'none';
  if(tab==='pp') genPassphrase(); else genPw();
}

function syncLen(){ document.getElementById('gen-len-disp').textContent=document.getElementById('gen-len').value; }
function useGenPw(){
  if(S.genPw){document.getElementById('f-password').value=S.genPw;checkStr(S.genPw);}
  closeModal('gen-modal'); if(S.fromEntry) openModal('entry-modal');
}

// ─── settings ─────────────────────────────────────────────────────────────────
async function openSettings(){
  setTimeout(()=>loadSmtpSettings(),200);  // still updates the configured label
  const firstBtn=document.querySelector('#settings-modal .tab-btn');
  if(firstBtn) showSettingsTab('tab-security',firstBtn);
  if(S.activeVault) await render2FAStatus(S.activeVault);
  renderCatListInSettings();
  renderVaultListInSettings();
  renderAccentSwatches();
  const shared=S.vaults.find(v=>v.id==='shared');
  const inp=document.getElementById('shared-path-input');
  if(inp&&shared) inp.value=shared.path||'';
  openModal('settings-modal');
}

async function saveSharedPath(){
  const inp=document.getElementById('shared-path-input');
  const path=(inp?inp.value:'').trim();
  if(!path){toast('Enter a path','error');return;}
  try{
    await api.vaultSetPath('shared',path);
    const vd=await api.vaults(); S.vaults=vd.vaults;
    const st=document.getElementById('shared-path-status');
    if(st){st.textContent='Saved.';setTimeout(()=>{if(st) st.textContent='';},3000);}
    toast('Shared vault path saved','success');
    renderVaultTabs(); renderVaultSwitcher();
  } catch(err){toast(err.message,'error');}
}
function openSharedPathModal(){ openSettings(); }
function openChangePw(){
  document.getElementById('new-pw-1').value='';
  document.getElementById('new-pw-2').value='';
  document.getElementById('changepw-err').textContent='';
  closeModal('settings-modal'); openModal('changepw-modal');
}
async function doChangePw(){
  const p1=document.getElementById('new-pw-1').value;
  const p2=document.getElementById('new-pw-2').value;
  const err=document.getElementById('changepw-err'); err.textContent='';
  if(p1.length<8){err.textContent='Password must be at least 8 characters.';return;}
  if(!/\d/.test(p1)){err.textContent='Password must contain at least one number.';return;}
  if(!/[^A-Za-z0-9]/.test(p1)){err.textContent='Password must contain a special character.';return;}
  if(p1!==p2){err.textContent='Passwords do not match.';return;}
  try{
    const res=await api.changePw(p1); S.tokens[S.activeVault]=res.token;
    closeModal('changepw-modal'); toast('Master password updated','success');
  } catch(e){err.textContent=e.message;}
}
async function saveAutolock(){
  const sel=document.getElementById('autolock-select'); if(!sel) return;
  try{await api.setAutolock(parseInt(sel.value));toast('Auto-lock updated','success');}
  catch(e){toast(e.message,'error');}
}

// ─── 2FA management ───────────────────────────────────────────────────────────
async function render2FAStatus(vaultId){
  const area=document.getElementById('twofa-status-area'); if(!area) return;
  try{
    const [totp, email, webauthn] = await Promise.all([
      api.twoFAStatus(vaultId),
      api.emailTwoFAStatus(vaultId).catch(()=>({enabled:false,email:''})),
      api.webauthnStatus(vaultId).catch(()=>({enabled:false}))
    ]);
    const anyEnabled = totp.enabled || email.enabled || webauthn.enabled;
    area.innerHTML='';
    const sec=document.createElement('div'); sec.className='settings-section';
    const h4=document.createElement('h4'); h4.textContent='Two-Factor Authentication';
    sec.appendChild(h4);

    // Build active method summary
    const methods=[];
    if(totp.enabled) methods.push('Authenticator App');
    if(email.enabled) methods.push('Email OTP');
    if(webauthn.enabled) methods.push('Security Key');

    const row=document.createElement('div');
    row.style.cssText='display:flex;align-items:center;justify-content:space-between;padding:10px 0';
    const info=document.createElement('div');
    const statusLine=document.createElement('div');
    statusLine.style.cssText='font-size:13px;font-weight:600;color:'+(anyEnabled?'var(--green)':'var(--text-2)');
    statusLine.textContent=anyEnabled?('\u2705 Active \u2014 '+methods.join(' + ')):'\uD83D\uDD13 Not configured';
    info.appendChild(statusLine);
    if(anyEnabled){
      const backupNote=document.createElement('div');
      backupNote.style.cssText='font-size:11px;color:var(--text-3);margin-top:3px';
      backupNote.textContent='Recovery codes available';
      info.appendChild(backupNote);
    }
    row.appendChild(info);

    const btnGroup=document.createElement('div');
    btnGroup.style.cssText='display:flex;gap:6px';
    if(anyEnabled){
      const editBtn=document.createElement('button');
      editBtn.className='btn-secondary'; editBtn.style.fontSize='12px'; editBtn.textContent='Edit 2FA';
      editBtn.onclick=()=>open2FAManage(vaultId);
      btnGroup.appendChild(editBtn);
    } else {
      const enBtn=document.createElement('button');
      enBtn.className='btn-save'; enBtn.style.fontSize='12px'; enBtn.textContent='Enable 2FA';
      enBtn.onclick=()=>open2FASetup(vaultId);
      btnGroup.appendChild(enBtn);
    }
    row.appendChild(btnGroup);
    sec.appendChild(row);
    area.appendChild(sec);
  } catch(e){
    area.innerHTML='<div style="color:var(--text-3);font-size:13px;padding:8px 0">Could not load 2FA status.</div>';
  }
}
function _2faRow(label, statusText, enabled, enabledColor, buttons){
  const item=document.createElement('div');
  item.style.cssText='display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)';
  const info=document.createElement('div');
  const nm=document.createElement('div'); nm.style.cssText='font-size:13px;font-weight:600;color:var(--text)'; nm.textContent=label;
  const st=document.createElement('div'); st.style.cssText='font-size:11px;margin-top:2px;color:'+(enabled?enabledColor:'var(--text-3)'); st.textContent=statusText;
  info.appendChild(nm); info.appendChild(st);
  const btnWrap=document.createElement('div'); btnWrap.style.cssText='display:flex;gap:6px;flex-shrink:0';
  buttons.forEach(b=>{
    const btn=document.createElement('button'); btn.className=b.cls; btn.textContent=b.label;
    btn.style.cssText='font-size:11px;padding:4px 10px;white-space:nowrap'; btn.onclick=b.fn;
    btnWrap.appendChild(btn);
  });
  item.appendChild(info); item.appendChild(btnWrap);
  return item;
}
async function doDisableEmailTwoFA(vaultId){
  if(!confirm('Disable Email OTP 2FA for this vault?')) return;
  try{ await api.emailTwoFADisable(vaultId); render2FAStatus(vaultId); toast('Email OTP disabled','info'); }
  catch(e){ toast(e.message,'error'); }
}
async function doDisableWebAuthn(vaultId){
  if(!confirm('Remove the registered security key from this vault?')) return;
  try{ await api.webauthnDisable(vaultId); render2FAStatus(vaultId); toast('Security key removed','info'); }
  catch(e){ toast(e.message,'error'); }
}

function open2FASetup(vaultId){
  S._2faVaultId = vaultId;
  document.getElementById('twofa-type-picker').style.display='';
  ['twofa-totp-setup','twofa-backup-setup','twofa-email-setup'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='none';
  });
  const wkEl=document.getElementById('twofa-webauthn-setup');
  if(wkEl) wkEl.style.display='none';
  document.getElementById('twofa-modal-title').textContent='Set Up Two-Factor Authentication';
  const footer=document.getElementById('twofa-modal-footer');
  if(footer) footer.innerHTML='<button class="btn-secondary" onclick="closeModal(\'twofa-setup-modal\')">Cancel</button>';
  // Clear any manage-mode badges
  document.querySelectorAll('.twofa-method-btn .twofa-badge').forEach(b=>b.remove());
  document.querySelectorAll('.twofa-method-btn').forEach(b=>{b.style.opacity='';b.onclick=b._origOnclick||b.onclick;});
  closeModal('settings-modal'); openModal('twofa-setup-modal');
}
async function open2FAManage(vaultId){
  S._2faVaultId = vaultId;
  document.getElementById('twofa-type-picker').style.display='';
  ['twofa-totp-setup','twofa-backup-setup','twofa-email-setup'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='none';
  });
  const wkEl=document.getElementById('twofa-webauthn-setup');
  if(wkEl) wkEl.style.display='none';
  document.getElementById('twofa-modal-title').textContent='Manage Two-Factor Authentication';
  const footer=document.getElementById('twofa-modal-footer');
  if(footer) footer.innerHTML='<button class="btn-secondary" onclick="closeModal(\'twofa-setup-modal\');openModal(\'settings-modal\')">Done</button>';
  closeModal('settings-modal'); openModal('twofa-setup-modal');
  // Fetch status and decorate tiles
  try{
    const [totp, email, webauthn] = await Promise.all([
      api.twoFAStatus(vaultId),
      api.emailTwoFAStatus(vaultId).catch(()=>({enabled:false})),
      api.webauthnStatus(vaultId).catch(()=>({enabled:false}))
    ]);
    const statusMap = {totp:totp.enabled, backup:false, email:email.enabled, webauthn:webauthn.enabled};
    document.querySelectorAll('.twofa-method-btn').forEach(btn=>{
      btn.querySelectorAll('.twofa-badge').forEach(b=>b.remove());
      const method = (btn.getAttribute('onclick')||'').match(/\'([a-z]+)\'/)?.[1];
      if(!method) return;
      const badge=document.createElement('span');
      badge.className='twofa-badge';
      if(statusMap[method]){
        badge.style.cssText='font-size:10px;color:var(--green);font-weight:700;margin-top:2px';
        badge.textContent='\u2713 Enabled';
        // Clicking enabled method → offer disable
        btn._origOnclick=btn.getAttribute('onclick');
        btn.setAttribute('onclick','');
        btn.onclick=()=>showDisable2FAOption(vaultId, method);
      } else {
        badge.style.cssText='font-size:10px;color:var(--text-3);margin-top:2px';
        badge.textContent='Not configured';
      }
      btn.appendChild(badge);
    });
  }catch(e){}
}
async function showDisable2FAOption(vaultId, method){
  const names={totp:'Authenticator App',email:'Email OTP',webauthn:'Security Key'};
  if(!confirm('Disable '+names[method]+'?')) return;
  try{
    if(method==='totp') await api.disable2FA(vaultId);
    else if(method==='email') await api.disableEmailTwoFA(vaultId);
    else if(method==='webauthn') await api.disableWebAuthn(vaultId);
    toast(names[method]+' disabled','success');
    closeModal('twofa-setup-modal');
    openModal('settings-modal');
    render2FAStatus(vaultId);
  }catch(e){ toast(e.message,'error'); }
}
// Open twofa-setup-modal and jump directly to a method (email, webauthn, backup)
async function openDirectSetup(vaultId, method){
  S._2faVaultId = vaultId;
  // Reset modal to clean state
  document.getElementById('twofa-type-picker').style.display='none';
  ['twofa-totp-setup','twofa-backup-setup','twofa-email-setup'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='none';
  });
  const wkEl=document.getElementById('twofa-webauthn-setup');
  if(wkEl) wkEl.style.display='none';
  const footer=document.getElementById('twofa-modal-footer');
  if(footer) footer.innerHTML='<button class="btn-secondary" onclick="open2FASetup(\''+vaultId+'\')">Back</button>';
  closeModal('settings-modal'); openModal('twofa-setup-modal');
  await selectTwofaMethod(method);
}


async function selectTwofaMethod(method){
  const vid = S._2faVaultId || S.activeVault;
  document.getElementById('twofa-type-picker').style.display='none';
  if(method === 'totp'){
    document.getElementById('twofa-modal-title').textContent='Authenticator App';
    try{
      const res = await api.twoFASetup(vid); S.twofaSecret=res.secret;
      const qr=document.getElementById('twofa-qr'); if(qr) qr.innerHTML=res.qr_svg;
      const sd=document.getElementById('twofa-secret-disp'); if(sd) sd.textContent=res.secret;
      const ce=document.getElementById('twofa-confirm-code'); if(ce) ce.value='';
      const ee=document.getElementById('twofa-err'); if(ee) ee.textContent='';
      document.getElementById('twofa-totp-setup').style.display='';
      const footer=document.getElementById('twofa-modal-footer');
      if(footer) footer.innerHTML=
        '<button class="btn-secondary" onclick="open2FASetup(S._2faVaultId)">Back</button>'+
        '<button class="btn-save" onclick="doEnable2FA()">Verify & Enable</button>';
      setTimeout(()=>{const el=document.getElementById('twofa-confirm-code');if(el)el.focus();},200);
    } catch(e){toast(e.message,'error'); open2FASetup(vid);}
  } else if(method === 'email'){
    document.getElementById('twofa-modal-title').textContent='Email OTP';
    // Keep picker visible until SMTP check completes - selectTwofaEmailSetup hides it
    selectTwofaEmailSetup();
    return;
  } else if(method === 'backup'){
    document.getElementById('twofa-modal-title').textContent='Backup Codes';
    try{
      const res = await api.backupCodes(vid);
      S._backupCodesPlain = res.codes;
      const grid=document.getElementById('twofa-backup-codes-grid'); grid.innerHTML='';
      res.codes.forEach(c=>{
        const d=document.createElement('div');
        d.style.cssText='background:var(--surface3);padding:6px 10px;border-radius:6px;text-align:center';
        d.textContent=c; grid.appendChild(d);
      });
      const cb=document.getElementById('backup-codes-confirm'); if(cb){cb.checked=false;}
      document.getElementById('twofa-backup-setup').style.display='';
      const footer=document.getElementById('twofa-modal-footer');
      if(footer) footer.innerHTML=
        '<button class="btn-secondary" onclick="open2FASetup(S._2faVaultId)">Back</button>'+
        '<button class="btn-save" id="twofa-backup-save-btn" onclick="finishBackupCodes()" disabled>Done - I Have Saved Them</button>';
    } catch(e){toast(e.message,'error'); open2FASetup(vid);}
  } else if(method === 'webauthn'){
    document.getElementById('twofa-modal-title').textContent='Security Key';
    document.getElementById('twofa-webauthn-setup').style.display='';
    document.getElementById('twofa-webauthn-err').textContent='';
    const footer=document.getElementById('twofa-modal-footer');
    if(footer) footer.innerHTML=
      '<button class="btn-secondary" onclick="open2FASetup(S._2faVaultId)">Back</button>'+
      '<button class="btn-save" onclick="doWebAuthnRegisterFlow()">Register Security Key</button>';
  }
}
function copyBackupCodes(){
  if(S._backupCodesPlain) copyField(S._backupCodesPlain.join('\n'),'Backup codes');
}
function copyBackupCodesView(){
  if(S._backupCodesViewPlain) copyField(S._backupCodesViewPlain.join('\n'),'Backup codes');
}
function finishBackupCodes(){
  closeModal('twofa-setup-modal');
  openModal('settings-modal');
  render2FAStatus(S.activeVault);
  toast('Backup codes saved. Store them somewhere safe.','success');
}
async function viewOrRegenBackupCodes(){
  const vid = S.activeVault;
  try{
    const res = await api.req('POST','/api/vaults/'+vid+'/2fa/backup-codes',{});
    S._backupCodesViewPlain = res.codes;
    const grid=document.getElementById('backup-codes-view-grid'); grid.innerHTML='';
    res.codes.forEach(c=>{
      const d=document.createElement('div');
      d.style.cssText='background:var(--surface3);padding:6px 10px;border-radius:6px;text-align:center';
      d.textContent=c; grid.appendChild(d);
    });
    openModal('backup-codes-modal');
  } catch(e){toast(e.message,'error');}
}
async function doEnable2FA(){
  const code=(document.getElementById('twofa-confirm-code').value||'').trim();
  const errEl=document.getElementById('twofa-err'); if(errEl) errEl.textContent='';
  if(!code||code.length<6){if(errEl) errEl.textContent='Enter the 6-digit code from your app';return;}
  try{
    await api.twoFAEnable(S.activeVault,S.twofaSecret,code); S.twofaSecret='';
    closeModal('twofa-setup-modal'); openModal('settings-modal');
    toast('2FA enabled \uD83D\uDEE1\uFE0F','success');
    render2FAStatus(S.activeVault);
    const vd=await api.vaults(); S.vaults=vd.vaults;
  } catch(e){
    if(errEl) errEl.textContent=e.message;
    const ce=document.getElementById('twofa-confirm-code'); if(ce){ce.value='';ce.focus();}
  }
}

async function doDisable2FA(vaultId){
  dangerConfirm({
    title: 'Disable 2FA',
    desc: 'Two-factor authentication will be removed from this vault. Anyone with the master password can unlock it without a code.',
    btnLabel: 'Disable 2FA',
    action: async () => {
      try{
        await api.twoFADisable(vaultId||S.activeVault);
        toast('2FA disabled','info'); render2FAStatus(S.activeVault);
        const vd=await api.vaults(); S.vaults=vd.vaults;
      } catch(e){toast(e.message,'error');}
    }
  }); 
}

// ─── category management ──────────────────────────────────────────────────────
function renderCatListInSettings(){
  const area=document.getElementById('cat-list-area'); if(!area) return;
  area.innerHTML='';
  if(!S.categories.length){area.innerHTML='<div style="color:var(--text-3);font-size:12px;padding:8px 0">No categories.</div>';return;}
  S.categories.forEach(cat=>{
    const item=document.createElement('div'); item.className='cat-list-item';
    const dot=document.createElement('span'); dot.className='color-dot'; dot.style.background=cat.color||'#64748b';
    const icon=document.createElement('span'); icon.style.fontSize='16px'; icon.textContent=cat.icon||'\uD83D\uDCC1';
    const lbl=document.createElement('span'); lbl.style.cssText='flex:1;font-size:13px;font-weight:500'; lbl.textContent=cat.label;
    const db=document.createElement('button'); db.className='btn-danger'; db.style.cssText='font-size:11px;padding:4px 8px';
    db.textContent='Remove'; db.onclick=()=>doDeleteCategory(cat.id);
    item.appendChild(dot); item.appendChild(icon); item.appendChild(lbl); item.appendChild(db); area.appendChild(item);
  });
}

function openAddCategoryModal(){
  document.getElementById('addcat-name').value='';
  document.getElementById('addcat-icon').value='';
  document.getElementById('addcat-color').value='#8b5cf6'; S.addCatColor='#8b5cf6';
  document.querySelectorAll('#addcat-colors .color-dot').forEach(d=>d.style.borderColor='transparent');
  const first=document.querySelector('#addcat-colors .color-dot'); if(first) first.style.borderColor='white';
  openModal('addcat-modal'); setTimeout(()=>document.getElementById('addcat-name').focus(),100);
}

function selectCatColor(el,color){
  document.querySelectorAll('#addcat-colors .color-dot').forEach(d=>d.style.borderColor='transparent');
  el.style.borderColor='white'; document.getElementById('addcat-color').value=color; S.addCatColor=color;
}

async function doAddCategory(){
  const name=(document.getElementById('addcat-name').value||'').trim();
  if(!name){toast('Enter a category name','error');return;}
  const icon=(document.getElementById('addcat-icon').value||'').trim()||'\uD83D\uDCC1';
  const color=document.getElementById('addcat-color').value||'#8b5cf6';
  try{
    await api.addCategory({label:name,icon,color});
    await loadCategories(); closeModal('addcat-modal'); renderCatListInSettings();
    toast('Category added','success');
  } catch(e){toast(e.message,'error');}
}

async function doDeleteCategory(id){
  const catObj = S.categories.find(c=>c.id===id);
  dangerConfirm({
    title: 'Remove Category',
    name: catObj ? catObj.label : id,
    desc: 'Entries in this category will be moved to Other.',
    btnLabel: 'Remove',
    action: async () => {
      try{
        await api.deleteCategory(id); await loadCategories(); renderCatListInSettings();
        toast('Category removed','info');
      } catch(e){toast(e.message,'error');}
    }
  });
}


// ── danger confirm ────────────────────────────────────────────────────────────
let _dcAction = null, _dcName = '';
function dangerConfirm({title, desc, name, btnLabel, action}){
  _dcAction = action; _dcName = name || '';
  document.getElementById('dc-title').textContent = title || 'Confirm';
  document.getElementById('dc-desc').textContent = desc || '';
  document.getElementById('dc-name').textContent = name || '';
  const inp = document.getElementById('dc-input');
  inp.value = ''; inp.placeholder = name || '';
  document.getElementById('dc-error').textContent = '';
  const btn = document.getElementById('dc-confirm-btn');
  btn.textContent = btnLabel || 'Delete'; btn.disabled = true;
  document.getElementById('dc-type-row').style.display = name ? 'block' : 'none';
  if(!name) btn.disabled = false;
  openModal('danger-confirm-modal');
  if(name) setTimeout(()=>inp.focus(), 150);
}
function checkDangerInput(){
  const inp=document.getElementById('dc-input');
  const match = inp.value === _dcName;
  document.getElementById('dc-confirm-btn').disabled = !match;
  const err = document.getElementById('dc-error');
  if(inp.value && !match) err.textContent = 'Name does not match';
  else err.textContent = '';
}
function closeDangerConfirm(){ _dcAction=null; _dcName=''; closeModal('danger-confirm-modal'); }
async function executeDangerConfirm(){
  if(document.getElementById('dc-confirm-btn').disabled) return;
  const fn=_dcAction; closeDangerConfirm(); if(fn) await fn();
}
// ─── vault management ─────────────────────────────────────────────────────────
function renderVaultListInSettings(){
  const area=document.getElementById('vault-list-area'); if(!area) return;
  area.innerHTML='';
  if(!S.vaults.length){area.innerHTML='<div style="color:var(--text-3);font-size:12px">No vaults</div>';return;}
  S.vaults.forEach(v=>{
    const item=document.createElement('div'); item.className='vault-list-item';
    const info=document.createElement('div'); info.className='vault-list-info';
    const name=document.createElement('span'); name.textContent=v.label+(v.shared?' (shared)':'');
    const path=document.createElement('small'); path.textContent=v.path||'not configured';
    info.appendChild(name); info.appendChild(path); item.appendChild(info);
    const db2=document.createElement('button'); db2.className='btn-danger';
    db2.style.cssText='font-size:11px;padding:4px 8px;white-space:nowrap';
    db2.textContent='Remove'; db2.onclick=()=>confirmDeleteVault(v.id,v.label);
    item.appendChild(db2);
    area.appendChild(item);
  });
}

async function openVaultManager(){
  const vd=await api.vaults(); S.vaults=vd.vaults;
  renderVaultListInManager(); openModal('vault-manager-modal');
}

function renderVaultListInManager(){
  const area=document.getElementById('vault-manager-list'); if(!area) return;
  area.innerHTML='';
  S.vaults.forEach(v=>{
    const item=document.createElement('div'); item.className='vault-list-item';
    const ic=document.createElement('span'); ic.style.fontSize='18px';
    ic.textContent=v.shared?'\uD83C\uDF10':'\uD83D\uDCBB';
    const info=document.createElement('div'); info.className='vault-list-info';
    const name=document.createElement('span'); name.textContent=v.label+(v.shared?' \u2022 Shared':'');
    const pe=document.createElement('small'); pe.textContent=v.path||'not configured';
    info.appendChild(name); info.appendChild(pe);
    const st=document.createElement('span'); st.style.cssText='font-size:11px;white-space:nowrap';
    const unlocked=!!S.tokens[v.id];
    st.textContent=unlocked?'\uD83D\uDD13 open':'\uD83D\uDD12 locked';
    st.style.color=unlocked?'var(--green)':'var(--text-3)';
    item.appendChild(ic); item.appendChild(info); item.appendChild(st);
    const db=document.createElement('button'); db.className='btn-danger';
    db.style.cssText='font-size:11px;padding:4px 8px;margin-left:8px;white-space:nowrap';
    db.textContent='Remove'; db.onclick=()=>confirmDeleteVault(v.id,v.label);
    item.appendChild(db);
    area.appendChild(item);
  });
}

function setVaultType(isShared){
  S.addVaultShared=isShared;
  document.getElementById('addvault-type-local').classList.toggle('active',!isShared);
  document.getElementById('addvault-type-shared').classList.toggle('active',isShared);
  const pr=document.getElementById('addvault-path-row');
  if(pr) pr.style.display=isShared?'block':'none';
  const mr=document.getElementById('addvault-mode-row');
  if(mr) mr.style.display=isShared?'block':'none';
  if(!isShared) setVaultMode('create');
}
function setVaultMode(mode){
  S.addVaultMode=mode;
  const isConnect=mode==='connect';
  const mNew=document.getElementById('addvault-mode-new'); if(mNew) mNew.classList.toggle('active',!isConnect);
  const mEx=document.getElementById('addvault-mode-existing'); if(mEx) mEx.classList.toggle('active',isConnect);
  const r2=document.getElementById('addvault-pw2-row'); if(r2) r2.style.display=isConnect?'none':'block';
  const hint=document.getElementById('addvault-pw-hint'); if(hint) hint.style.display=isConnect?'none':'block';
  const btn=document.getElementById('addvault-submit'); if(btn) btn.textContent=isConnect?'Connect Vault':'Create Vault';
  const pwField=document.getElementById('addvault-pw');
  if(pwField) pwField.placeholder=isConnect?'Enter vault password':'Minimum 8 characters';
}

function openAddVaultModal(isShared){
  S.addVaultShared=!!isShared; S._newVaultId=null; S.addVaultMode='create';
  setVaultType(!!isShared);
  document.getElementById('addvault-name').value='';
  const pe=document.getElementById('addvault-path'); if(pe) pe.value='';
  const pw=document.getElementById('addvault-pw'); if(pw) pw.value='';
  const pw2=document.getElementById('addvault-pw2'); if(pw2) pw2.value='';
  const err=document.getElementById('addvault-error'); if(err) err.textContent='';
  // Reset wizard to step1
  const s1=document.getElementById('addvault-step1'); if(s1){s1.classList.add('active');s1.style.display='';}
  const s2=document.getElementById('addvault-step2'); if(s2){s2.classList.remove('active');s2.style.display='none';}
  const fa=document.getElementById('addvault-2fa-area'); if(fa) fa.style.display='none';
  const footer=document.getElementById('addvault-footer');
  if(footer){
    footer.innerHTML='<button class="btn-secondary" id="addvault-cancel-btn" onclick="closeModal(\'addvault-modal\')">Cancel</button>'+
                     '<button class="btn-save" id="addvault-submit" onclick="doAddVault()">Create Vault</button>';
  }
  openModal('addvault-modal');
  setTimeout(()=>document.getElementById('addvault-name').focus(),100);
}

async function doAddVault(){
  const errEl=document.getElementById('addvault-error');
  const label=(document.getElementById('addvault-name').value||'').trim();
  if(!label){errEl.textContent='Vault name is required';return;}
  const pe=document.getElementById('addvault-path');
  const path=pe?pe.value.trim():'';
  if(S.addVaultShared&&!path){errEl.textContent='File path is required for shared vaults';return;}
  if(S.addVaultShared&&path&&!path.toLowerCase().endsWith('.json')){
    errEl.textContent='Shared vault path must be a .json file (e.g. \\\\server\\share\\vault.json)';return;
  }
  const pw=(document.getElementById('addvault-pw').value||'').trim();
  // ── Connect Existing Shared Vault branch ─────────────────────────────────
  if(S.addVaultShared && S.addVaultMode==='connect'){
    if(!pw){errEl.textContent='Password is required';return;}
    const btn=document.getElementById('addvault-submit');
    if(btn){btn.textContent='Connecting...';btn.disabled=true;}
    try{
      const vault=await api.addVault({label,shared:true,path});
      let res;
      try{ res=await api.vaultUnlock(vault.id,pw); }
      catch(unlockErr){
        try{ await api.deleteVault(vault.id); }catch(x){}
        throw unlockErr;
      }
      S.tokens[vault.id]=res.token;
      const vd=await api.vaults(); S.vaults=vd.vaults;
      closeModal('addvault-modal');
      await switchVault(vault.id);
      toast('"'+label+'" connected successfully','success');
    }catch(e){
      errEl.textContent=e.message;
      if(btn){btn.textContent='Connect Vault';btn.disabled=false;}
    }
    return;
  }
  // ── Create New Vault branch ───────────────────────────────────────────────
  if(pw.length<8){errEl.textContent='Password must be at least 8 characters';return;}
  if(!/\d/.test(pw)){errEl.textContent='Password must contain at least one number';return;}
  if(!/[^A-Za-z0-9]/.test(pw)){errEl.textContent='Password must contain a special character (e.g. !@#$%)';return;}
  const pw2=(document.getElementById('addvault-pw2').value||'').trim();
  if(pw!==pw2){errEl.textContent='Passwords do not match';return;}
  const btn=document.getElementById('addvault-submit');
  if(btn){btn.textContent='Creating...';btn.disabled=true;}
  try{
    const vault=await api.addVault({label,shared:S.addVaultShared,path});
    let res;
    try{ res=await api.vaultCreate(vault.id,pw); }
    catch(createErr){
      // rollback - remove vault from config since file wasn't created
      try{ await api.deleteVault(vault.id); }catch(x){}
      throw createErr;
    }
    S.tokens[vault.id]=res.token;
    const vd=await api.vaults(); S.vaults=vd.vaults;
    S._newVaultId = vault.id;
    // Move to step2 (2FA offer)
    const s1=document.getElementById('addvault-step1'); if(s1){s1.classList.remove('active');s1.style.display='none';}
    const s2=document.getElementById('addvault-step2'); if(s2){s2.classList.add('active');s2.style.display='';}
    const nameEl=document.getElementById('addvault-created-name'); if(nameEl) nameEl.textContent='"'+label+'" is ready!';
    const footer=document.getElementById('addvault-footer');
    if(footer){
      footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSkip2FA()">Skip for Now</button>'+
                       '<button class="btn-save" onclick="doAddVaultSetup2FA()">&#128272; Enable 2FA</button>';
    }
    if(btn){btn.textContent='Create Vault';btn.disabled=false;}
  } catch(e){
    errEl.textContent=e.message;
    if(btn){btn.textContent='Create Vault';btn.disabled=false;}
  }
}

async function doAddVaultSetup2FA(){
  // Show the 2FA type picker
  ['addvault-2fa-area','addvault-backup-area','addvault-email-area'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='none';
  });
  const picker = document.getElementById('addvault-2fa-picker');
  if(picker) picker.style.display='grid';
  const footer = document.getElementById('addvault-footer');
  if(footer) footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSkip2FA()">Skip for Now</button>';
}
async function doAddVaultSelectMethod(method){
  const id = S._newVaultId; if(!id) return;
  const picker = document.getElementById('addvault-2fa-picker');
  if(picker) picker.style.display='none';
  ['addvault-2fa-area','addvault-backup-area','addvault-email-area'].forEach(eid=>{
    const el=document.getElementById(eid); if(el) el.style.display='none';
  });
  const footer = document.getElementById('addvault-footer');
  if(method==='totp'){
    try{
      const r = await api.twoFASetup(id); S.twofaSecret=r.secret;
      const qrEl=document.getElementById('addvault-qr'); if(qrEl&&r.qr_svg) qrEl.innerHTML=r.qr_svg;
      const secEl=document.getElementById('addvault-2fa-secret'); if(secEl) secEl.textContent=r.secret;
      document.getElementById('addvault-2fa-code').value='';
      document.getElementById('addvault-2fa-error').textContent='';
      document.getElementById('addvault-2fa-area').style.display='block';
      if(footer) footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSetup2FA()">Back</button>'+
        '<button class="btn-save" onclick="doAddVaultEnable2FA()">Verify & Enable</button>';
      setTimeout(()=>{const el=document.getElementById('addvault-2fa-code');if(el)el.focus();},200);
    }catch(e){toast(e.message,'error'); doAddVaultSetup2FA();}
  } else if(method==='backup'){
    try{
      const r = await api.backupCodes(id);
      const grid=document.getElementById('addvault-backup-grid'); grid.innerHTML='';
      r.codes.forEach(c=>{
        const d=document.createElement('div');
        d.style.cssText='background:var(--surface3);padding:6px 10px;border-radius:6px;text-align:center';
        d.textContent=c; grid.appendChild(d);
      });
      const cb=document.getElementById('addvault-backup-confirm'); if(cb) cb.checked=false;
      document.getElementById('addvault-backup-area').style.display='block';
      if(footer) footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSetup2FA()">Back</button>'+
        '<button class="btn-save" id="addvault-backup-save-btn" onclick="doAddVaultSkip2FA()" disabled>Done - I Saved Them</button>';
    }catch(e){toast(e.message,'error'); doAddVaultSetup2FA();}
  } else if(method==='email'){
    try{
      const smtp=await api.smtpGet();
      if(!smtp.host){
        // SMTP not configured: open SMTP modal directly (same popup as inside the vault)
        // Close addvault-modal first so smtp-modal (earlier in DOM) renders on top
        closeModal('addvault-modal');
        openSmtpModal(
          ()=>{ openModal('addvault-modal'); doAddVaultSelectMethod('email'); },
          ()=>{ openModal('addvault-modal'); doAddVaultSetup2FA(); }
        );
        return;
      }
    }catch(e){ toast(e.message,'error'); doAddVaultSetup2FA(); return; }
    // SMTP is configured - go straight to email address input
    document.getElementById('addvault-email-addr').value='';
    document.getElementById('addvault-email-error').textContent='';
    document.getElementById('addvault-email-area').style.display='block';
    if(footer) footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSetup2FA()">Back</button>'+
      '<button class="btn-save" onclick="doAddVaultEnableEmailOTP()">Enable Email OTP</button>';
    setTimeout(()=>document.getElementById('addvault-email-addr').focus(),150);
  } else if(method==='webauthn'){
    // WebAuthn during vault creation - open twofa-setup-modal for webauthn registration
    // Store new vault id and switch to settings-style webauthn flow
    S._2faVaultId = S._newVaultId;
    closeModal('addvault-modal');
    document.getElementById('twofa-type-picker').style.display='none';
    ['twofa-totp-setup','twofa-backup-setup','twofa-email-setup'].forEach(id=>{
      const el=document.getElementById(id); if(el) el.style.display='none';
    });
    const wkEl=document.getElementById('twofa-webauthn-setup');
    if(wkEl) wkEl.style.display='';
    document.getElementById('twofa-webauthn-err').textContent='';
    document.getElementById('twofa-modal-title').textContent='Security Key';
    const tfooter=document.getElementById('twofa-modal-footer');
    if(tfooter) tfooter.innerHTML=
      '<button class="btn-secondary" onclick="closeModal(\'twofa-setup-modal\');openModal(\'addvault-modal\');doAddVaultSetup2FA()">Back</button>'+
      '<button class="btn-save" onclick="doWebAuthnRegisterFlow()">Register Security Key</button>';
    openModal('twofa-setup-modal');
  }
}
function onAddVaultBackupConfirm(cb){
  const btn=document.getElementById('addvault-backup-save-btn'); if(btn) btn.disabled=!cb.checked;
}
async function doAddVaultEnableEmailOTP(){
  const id=S._newVaultId; if(!id) return;
  const email=(document.getElementById('addvault-email-addr').value||'').trim();
  const err=document.getElementById('addvault-email-error');
  if(!email||!email.includes('@')){err.textContent='Enter a valid email address';return;}
  const btn=document.querySelector('#addvault-footer .btn-save');
  if(btn){btn.textContent='Saving...';btn.disabled=true;}
  try{
    await api.emailTwoFASetup(id,email);
    closeModal('addvault-modal'); await switchVault(id);
    toast('Vault created with Email OTP enabled!','success');
  }catch(e){
    err.textContent=e.message;
    if(btn){btn.textContent='Enable Email OTP';btn.disabled=false;}
  }
}
async function doAddVaultEnable2FA(){
  const id = S._newVaultId; if(!id) return;
  const code = (document.getElementById('addvault-2fa-code').value||'').trim();
  if(code.length !== 6){ document.getElementById('addvault-2fa-error').textContent='Enter the 6-digit code from your app'; return; }
  const btn = document.querySelector('#addvault-footer .btn-save');
  if(btn){ btn.textContent='Verifying...'; btn.disabled=true; }
  try{
    await api.twoFAEnable(id, S.twofaSecret, code);
    closeModal('addvault-modal');
    await switchVault(id);
    toast('Vault created with 2FA enabled!','success');
  } catch(e){
    document.getElementById('addvault-2fa-error').textContent = e.message;
    if(btn){ btn.textContent='Verify & Enable'; btn.disabled=false; }
  }
}
async function doAddVaultSkip2FA(){
  const id = S._newVaultId;
  closeModal('addvault-modal');
  if(id) await switchVault(id);
  toast('Vault created. You can enable 2FA later in Settings.','success');
}


function checkLockedVaultDel(){
  const v = S.vaults.find(x=>x.id===S._lockedDelVaultId);
  const isUnlocked = v && !!S.tokens[v.id];
  const nameOk = document.getElementById('lvd-name-input').value === (v?v.label:'');
  const pw = document.getElementById('lvd-password').value;
  const pwOk = isUnlocked || pw.length > 0;
  document.getElementById('lvd-confirm-btn').disabled = !(nameOk && pwOk);
  if(document.getElementById('lvd-name-input').value && !nameOk)
    document.getElementById('lvd-error').textContent = 'Name does not match';
  else document.getElementById('lvd-error').textContent = '';
}
async function doLockedVaultDelete(){
  const id = S._lockedDelVaultId;
  const pw = document.getElementById('lvd-password').value;
  const btn = document.getElementById('lvd-confirm-btn');
  btn.textContent='Removing...'; btn.disabled=true;
  try{
    const v = S.vaults.find(x=>x.id===id);
    if(!v) throw new Error('Vault not found');
    const isUnlocked = !!S.tokens[id];
    if(!isUnlocked){
      // Verify password by attempting unlock
      const res = await api.vaultUnlock(id, pw, '');
      if(res.needs_2fa) throw new Error('Cannot delete while 2FA is pending - unlock first');
      // Lock immediately after verify
      try{ await api.vaultLock(id); }catch(x){}
    }
    closeModal('locked-vault-del-modal');
    await doDeleteVault(id);
  } catch(e){
    document.getElementById('lvd-error').textContent = e.message.includes('password') ? 'Incorrect password' : e.message;
    btn.textContent='Remove Vault'; btn.disabled=false;
  }
}
function confirmDeleteVault(id,label){
  // Always use name+password modal for vault deletion
  S._lockedDelVaultId = id;
  const isUnlocked = !!S.tokens[id];
  document.getElementById('lvd-name').textContent = label;
  document.getElementById('lvd-name-input').value = '';
  document.getElementById('lvd-password').value = '';
  document.getElementById('lvd-error').textContent = '';
  const lvdBtn = document.getElementById('lvd-confirm-btn');
  lvdBtn.textContent = 'Remove Vault'; lvdBtn.disabled = true;
  // Show/hide password field based on lock state
  const pwRow = document.getElementById('lvd-pw-row');
  if(pwRow) pwRow.style.display = isUnlocked ? 'none' : '';
  openModal('locked-vault-del-modal');
  setTimeout(()=>document.getElementById('lvd-name-input').focus(),150);
}

async function doDeleteVault(id){
  try{
    await api.deleteVault(id); delete S.tokens[id];
    const vd=await api.vaults(); S.vaults=vd.vaults;
    // Close any open modals before transitioning
    ['settings-modal','vault-manager-modal','vault-edit-modal','danger-confirm-modal','locked-vault-del-modal'].forEach(mid=>closeModal(mid));
    renderVaultTabs(); renderVaultSwitcher();
    renderVaultListInSettings(); renderVaultListInManager();
    toast('Vault removed','info');
    S.activeVault=null;
    document.getElementById('app').style.display='none';
    const other=S.vaults.find(v=>S.tokens[v.id]);
    if(other) switchVault(other.id);
    else showUnlockScreen(S.vaults.length ? S.vaults[0].id : null);
  } catch(e){toast(e.message,'error');}
}

// ─── password health ──────────────────────────────────────────────────────────
async function openHealth(){
  openModal('health-modal');
  const body=document.getElementById('health-body');
  body.innerHTML='<div style="text-align:center;padding:40px;color:var(--text-3)">Analyzing...</div>';
  try{const r=await api.health();renderHealthReport(r);updateHealthBadge(r);}
  catch(e){body.innerHTML=`<div style="color:var(--red);padding:16px">${e.message}</div>`;}
}

function renderHealthReport(r){
  const body=document.getElementById('health-body'); body.innerHTML='';
  const score=r.score||0;
  const sw=document.createElement('div'); sw.className='health-score-wrap';
  const se=document.createElement('div'); se.className='health-score';
  se.style.color=strColor(score); se.textContent=score;
  const sl=document.createElement('div'); sl.className='health-score-label';
  sl.textContent=score>=80?'Excellent':score>=60?'Good':score>=40?'Fair':'Needs Attention';
  sw.appendChild(se); sw.appendChild(sl); body.appendChild(sw);
  function addSection(title,items,detailFn){
    if(!items||!items.length) return;
    const h=document.createElement('div'); h.className='health-section-title';
    h.textContent=title+' ('+items.length+')'; body.appendChild(h);
    items.slice(0,20).forEach(entry=>{
      const item=document.createElement('div'); item.className='health-item';
      const av=document.createElement('div'); av.className='entry-avatar '+avCls(entry.title);
      av.style.cssText='width:32px;height:32px;font-size:14px;border-radius:8px';
      av.textContent=avChar(entry.title);
      const info=document.createElement('div'); info.className='health-item-name'; info.textContent=entry.title;
      const det=document.createElement('div'); det.className='health-item-detail'; det.textContent=detailFn(entry);
      const fb=document.createElement('button'); fb.className='btn-secondary';
      fb.style.cssText='font-size:11px;padding:4px 8px'; fb.textContent='Fix';
      fb.onclick=()=>{closeModal('health-modal');openEditEntry(entry.id);};
      item.appendChild(av); item.appendChild(info); item.appendChild(det); item.appendChild(fb);
      body.appendChild(item);
    });
  }
  addSection('\u26A0\uFE0F Weak Passwords',r.weak,()=>'Weak password');
  addSection('\uD83D\uDD04 Reused Passwords',r.reused,()=>'Reused across entries');
  addSection('\u231B Old Passwords',r.old,e=>'Not changed in '+Math.round((Date.now()/1000-e.updated_at)/86400)+' days');
  if((!r.weak||!r.weak.length)&&(!r.reused||!r.reused.length)&&(!r.old||!r.old.length)){
    const g=document.createElement('div');
    g.style.cssText='text-align:center;padding:24px;color:var(--green);font-size:14px;font-weight:600';
    g.textContent='\u2705 All passwords look healthy!'; body.appendChild(g);
  }
}

function getExpiryWarnings(){
  const today=new Date(); const soon=new Date(today); soon.setDate(soon.getDate()+30);
  const expired=S.entries.filter(e=>e.expiry_date&&new Date(e.expiry_date)<today);
  const expiring=S.entries.filter(e=>e.expiry_date&&new Date(e.expiry_date)>=today&&new Date(e.expiry_date)<=soon);
  return {expired,expiring};
}
function updateHealthBadge(r){
  const badge=document.getElementById('health-badge'); if(!badge) return;
  const issues=((r.weak||[]).length+(r.reused||[]).length);
  if(issues>0){badge.textContent=issues>99?'99+':String(issues);badge.style.display='';}
  else{badge.textContent='';badge.style.display='none';}
}

// ─── counts / nav helpers / init ──────────────────────────────────────────────
function updateCounts(){
  const ae=document.getElementById('count-all'); if(ae) ae.textContent=S.entries.length;
  const fe=document.getElementById('count-favorites'); if(fe) fe.textContent=S.entries.filter(e=>e.favorite).length;
  S.categories.forEach(cat=>{
    const el=document.getElementById('count-'+cat.id); if(el) el.textContent=S.entries.filter(e=>e.category===cat.id).length;
  });
}

function setCat(el){
  document.querySelectorAll('.nav-item[data-cat]').forEach(n=>n.classList.remove('active'));
  el.classList.add('active'); S.cat=el.dataset.cat; applyFilter();
}
function onSearch(q){ S.q=(q||'').toLowerCase(); applyFilter(); }

// ─── breach check (HIBP k-anonymity) ─────────────────────────────────────────
async function sha1hex(str){
  const buf=await crypto.subtle.digest('SHA-1',new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
}

async function checkBreach(pw,resultEl,btnEl){
  if(!pw){toast('No password to check','info');return;}
  if(resultEl) resultEl.className='breach-checking'; if(resultEl) resultEl.textContent='Checking...';
  if(btnEl) btnEl.disabled=true;
  try{
    const hash=await sha1hex(pw);
    const prefix=hash.slice(0,5), suffix=hash.slice(5);
    const res=await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if(!res.ok) throw new Error('HIBP unavailable');
    const text=await res.text();
    const found=text.split('\r\n').find(l=>l.startsWith(suffix));
    if(found){
      const count=parseInt(found.split(':')[1],10);
      if(resultEl){resultEl.className='breach-pwned';resultEl.textContent=`\u26A0\uFE0F Found in ${count.toLocaleString()} breaches!`;}
      toast('Password found in '+count.toLocaleString()+' data breaches!','error');
    } else {
      if(resultEl){resultEl.className='breach-safe';resultEl.textContent='\u2705 Not found in known breaches';}
      toast('Password not found in known breaches','success');
    }
  } catch(e){
    if(resultEl){resultEl.className='breach-checking';resultEl.textContent='Check failed (offline?)';}
  } finally {
    if(btnEl) btnEl.disabled=false;
  }
}



// ── Forgot Password ──────────────────────────────────────────────────────────
function openForgotPassword(){
  const v=S.vaults.find(x=>x.id===S.unlockVaultId);
  if(!v||!v.has_email2fa) return;
  document.getElementById('forgot-step-send').style.display='block';
  document.getElementById('forgot-step-verify').style.display='none';
  document.getElementById('forgot-step-done').style.display='none';
  document.getElementById('forgot-send-hint').textContent='';
  document.getElementById('forgot-send-error').textContent='';
  document.getElementById('forgot-verify-error').textContent='';
  document.getElementById('forgot-unlock-error').textContent='';
  const codeEl=document.getElementById('forgot-code-input');
  if(codeEl) codeEl.value='';
  const pwEl=document.getElementById('forgot-pw-input');
  if(pwEl) pwEl.value='';
  openModal('forgot-pw-modal');
}

async function doForgotSend(){
  const v=S.vaults.find(x=>x.id===S.unlockVaultId);
  if(!v) return;
  const errEl=document.getElementById('forgot-send-error');
  errEl.textContent='';
  const sendBtn=document.querySelector('#forgot-step-send .btn-primary');
  if(sendBtn){sendBtn.disabled=true;sendBtn.textContent='Sending...';}
  try{
    const r=await fetch('/api/vaults/'+v.id+'/forgot-password/send',{method:'POST'});
    const d=await r.json();
    if(sendBtn){sendBtn.disabled=false;sendBtn.textContent='Send Verification Code';}
    if(!r.ok){errEl.textContent=d.error||'Failed to send code';return;}
    document.getElementById('forgot-email-hint').textContent=d.email_hint||'your email';
    document.getElementById('forgot-step-send').style.display='none';
    document.getElementById('forgot-step-verify').style.display='block';
    setTimeout(()=>{const el=document.getElementById('forgot-code-input');if(el)el.focus();},100);
  }catch(e){
    if(sendBtn){sendBtn.disabled=false;sendBtn.textContent='Send Verification Code';}
    errEl.textContent='Network error';
  }
}

async function doForgotVerify(){
  const code=(document.getElementById('forgot-code-input').value||'').trim();
  const errEl=document.getElementById('forgot-verify-error');
  errEl.textContent='';
  if(!code){errEl.textContent='Enter the 6-digit code';return;}
  const v=S.vaults.find(x=>x.id===S.unlockVaultId);
  if(!v) return;
  const verBtn=document.querySelector('#forgot-step-verify .btn-primary');
  if(verBtn){verBtn.disabled=true;verBtn.textContent='Verifying...';}
  try{
    const r=await fetch('/api/vaults/'+v.id+'/forgot-password/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
    const d=await r.json();
    if(verBtn){verBtn.disabled=false;verBtn.textContent='Verify Code';}
    if(!r.ok){errEl.textContent=d.error||'Invalid code';return;}
    document.getElementById('forgot-step-verify').style.display='none';
    document.getElementById('forgot-step-done').style.display='block';
    setTimeout(()=>{const el=document.getElementById('forgot-pw-input');if(el)el.focus();},100);
  }catch(e){
    if(verBtn){verBtn.disabled=false;verBtn.textContent='Verify Code';}
    errEl.textContent='Network error';
  }
}

async function doForgotUnlock(){
  const pw=(document.getElementById('forgot-pw-input').value||'').trim();
  const errEl=document.getElementById('forgot-unlock-error');
  errEl.textContent='';
  if(!pw){errEl.textContent='Enter your password';return;}
  const v=S.vaults.find(x=>x.id===S.unlockVaultId);
  if(!v) return;
  try{
    const r=await fetch('/api/vaults/'+v.id+'/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(!r.ok){errEl.textContent=d.error||'Incorrect password';return;}
    if(d.token){
      S.tokens[v.id]=d.token;
      closeModal('forgot-pw-modal');
      switchVault(v.id);
    }
  }catch(e){
    errEl.textContent='Network error';
  }
}

async function doForgotRemove(){
  const v=S.vaults.find(x=>x.id===S.unlockVaultId);
  if(!v) return;
  if(!confirm('Remove vault "'+v.label+'"? All encrypted data will be permanently deleted. This cannot be undone.')) return;
  try{
    await fetch('/api/vaults/'+v.id,{method:'DELETE'});
    closeModal('forgot-pw-modal');
    const vd=await api.vaults(); S.vaults=vd.vaults;
    renderVaultTabs(); renderVaultSwitcher();
    showUnlockScreen(S.vaults.length?S.vaults[0].id:null);
    toast('Vault removed','info');
  }catch(e){
    toast('Failed to remove vault','error');
  }
}


// ─── Auto-lock countdown ──────────────────────────────────────────────────────
function startLockCountdown(seconds){
  stopLockCountdown();
  if(!seconds||seconds<=0) return;
  S.autolock=seconds;
  S.lockAt=Date.now()+(seconds*1000);
  S.lockWarningShown=false;
  S.lockInterval=setInterval(()=>{
    if(!S.activeVault){stopLockCountdown();return;}
    const rem=Math.ceil((S.lockAt-Date.now())/1000);
    if(rem<=0){stopLockCountdown();autoLockFire();return;}
    if(rem<=30&&!S.lockWarningShown){
      S.lockWarningShown=true;
      showLockWarningBar(rem);
    } else if(rem<=30){
      const msg=document.getElementById('lock-warning-msg');
      if(msg) msg.textContent='Vault locking in '+rem+'s';
    } else if(rem>30&&S.lockWarningShown){
      S.lockWarningShown=false;
      hideLockWarningBar();
    }
  },1000);
  // Reset countdown on any user activity in the app
  const app=document.getElementById('app');
  if(app&&!app._lockListenerSet){
    app._lockListenerSet=true;
    ['click','keydown','mousemove','scroll'].forEach(ev=>
      app.addEventListener(ev,()=>resetLockCountdown(),{passive:true})
    );
  }
}
function stopLockCountdown(){
  if(S.lockInterval){clearInterval(S.lockInterval);S.lockInterval=null;}
  hideLockWarningBar();
  S.lockWarningShown=false;
}
function resetLockCountdown(){
  if(!S.lockInterval||!S.autolock) return;
  S.lockAt=Date.now()+(S.autolock*1000);
  if(S.lockWarningShown){S.lockWarningShown=false;hideLockWarningBar();}
}
function showLockWarningBar(rem){
  const bar=document.getElementById('lock-warning-bar');
  const msg=document.getElementById('lock-warning-msg');
  if(bar){bar.style.display='flex';}
  if(msg) msg.textContent='Vault locking in '+rem+'s';
  // Shift main content down
  const main=document.getElementById('main');
  if(main) main.style.paddingTop='37px';
}
function hideLockWarningBar(){
  const bar=document.getElementById('lock-warning-bar');
  if(bar) bar.style.display='none';
  const main=document.getElementById('main');
  if(main) main.style.paddingTop='';
}
async function stayActive(){
  resetLockCountdown();
  try{ await api.sessionTouch(); }catch(e){}
  hideLockWarningBar();
  S.lockWarningShown=false;
}
async function autoLockFire(){
  const vid=S.activeVault; if(!vid) return;
  try{ await api.vaultLock(vid); }catch(e){}
  delete S.tokens[vid];
  // Keep pinData so PIN unlock works after auto-lock
  stopLockCountdown();
  const vd=await api.vaults(); S.vaults=vd.vaults;
  toast('Vault auto-locked','info');
  const other=S.vaults.find(v=>S.tokens[v.id]);
  if(other){switchVault(other.id);}
  else{S.activeVault=null;showUnlockScreen(vid);}
}

// ─── PIN quick-unlock ─────────────────────────────────────────────────────────
async function _pinDeriveKey(pin, saltHex){
  const enc=new TextEncoder();
  const keyMat=await crypto.subtle.importKey('raw',enc.encode(pin),{name:'PBKDF2'},false,['deriveKey']);
  const salt=new Uint8Array(saltHex.match(/.{2}/g).map(b=>parseInt(b,16)));
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},
    keyMat,{name:'AES-GCM',length:256},false,['encrypt','decrypt']
  );
}
function _bufToHex(buf){ return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function _hexToBuf(hex){ return new Uint8Array(hex.match(/.{2}/g).map(b=>parseInt(b,16))).buffer; }

function storePinSession(vaultId, masterPassword){
  // Store master password in session memory if there's a PIN configured for this vault
  if(!masterPassword) return;
  const stored=localStorage.getItem('pm_pin_'+vaultId);
  if(stored) S.pinData[vaultId]={masterPassword};
}

function openPinSetup(){
  const vid=S.activeVault; if(!vid) return;
  const hasPin=!!localStorage.getItem('pm_pin_'+vid);
  document.getElementById('pin-modal-title').textContent=hasPin?'Manage Quick-Unlock PIN':'Set Quick-Unlock PIN';
  document.getElementById('pin-setup-form').style.display=hasPin?'none':'block';
  document.getElementById('pin-clear-form').style.display=hasPin?'block':'none';
  document.getElementById('pin-new-1').value='';
  document.getElementById('pin-new-2').value='';
  document.getElementById('pin-setup-error').textContent='';
  const footer=document.getElementById('pin-modal-footer');
  if(hasPin){
    footer.innerHTML='<button class="btn-secondary" onclick="closeModal(\'pin-setup-modal\')">Cancel</button>'+
      '<button class="btn-danger" onclick="clearPin()">Remove PIN</button>'+
      '<button class="btn-save" onclick="document.getElementById(\'pin-setup-form\').style.display=\'block\';document.getElementById(\'pin-clear-form\').style.display=\'none\';this.closest(\'.modal-footer\').innerHTML=\'<button class=&quot;btn-secondary&quot; onclick=&quot;closeModal(\\\'pin-setup-modal\\\')&quot;>Cancel</button><button class=&quot;btn-save&quot; onclick=&quot;savePinSetup()&quot;>Save PIN</button>\'">Change PIN</button>';
  } else {
    footer.innerHTML='<button class="btn-secondary" onclick="closeModal(\'pin-setup-modal\')">Cancel</button><button class="btn-save" onclick="savePinSetup()">Save PIN</button>';
  }
  updatePinStatusLabel();
  openModal('pin-setup-modal');
}
async function savePinSetup(){
  const vid=S.activeVault; if(!vid) return;
  const p1=document.getElementById('pin-new-1').value;
  const p2=document.getElementById('pin-new-2').value;
  const errEl=document.getElementById('pin-setup-error');
  errEl.textContent='';
  if(!/^\d{6}$/.test(p1)){errEl.textContent='PIN must be exactly 6 digits';return;}
  if(p1!==p2){errEl.textContent='PINs do not match';return;}
  // Encrypt master password with PIN
  const session=S.pinData[vid];
  const masterPw=session&&session.masterPassword;
  if(!masterPw){errEl.textContent='Vault must be unlocked to set a PIN';return;}
  try{
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const saltHex=_bufToHex(salt.buffer);
    const key=await _pinDeriveKey(p1,saltHex);
    const enc=new TextEncoder();
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(masterPw));
    localStorage.setItem('pm_pin_'+vid,JSON.stringify({salt:saltHex,iv:_bufToHex(iv.buffer),ct:_bufToHex(ct)}));
    S.pinData[vid]={masterPassword:masterPw};
    closeModal('pin-setup-modal');
    updatePinStatusLabel();
    toast('PIN set. You can now use it to re-unlock after auto-lock.','success');
  }catch(e){errEl.textContent='Failed to save PIN: '+e.message;}
}
function clearPin(){
  const vid=S.activeVault; if(!vid) return;
  localStorage.removeItem('pm_pin_'+vid);
  S.pinData[vid]=null;
  closeModal('pin-setup-modal');
  updatePinStatusLabel();
  toast('PIN removed','info');
}
function updatePinStatusLabel(){
  const lbl=document.getElementById('pin-status-label'); if(!lbl) return;
  const vid=S.activeVault;
  lbl.textContent=vid&&localStorage.getItem('pm_pin_'+vid)?'PIN configured':'Not configured';
}
async function doPinUnlock(){
  const vid=S.unlockVaultId; if(!vid) return;
  const pin=document.getElementById('pin-unlock-input').value;
  const errEl=document.getElementById('pin-unlock-error');
  errEl.textContent='';
  if(!/^\d{6}$/.test(pin)){errEl.textContent='Enter your 6-digit PIN';return;}
  const stored=localStorage.getItem('pm_pin_'+vid);
  if(!stored){errEl.textContent='No PIN configured for this vault';return;}
  try{
    const {salt,iv,ct}=JSON.parse(stored);
    const key=await _pinDeriveKey(pin,salt);
    const dec=new TextDecoder();
    const ptBuf=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(_hexToBuf(iv))},key,_hexToBuf(ct));
    const masterPw=dec.decode(ptBuf);
    // Use master password to unlock
    const vault=S.vaults.find(v=>v.id===vid);
    const res=await fetch('/api/vaults/'+vid+'/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:masterPw})});
    const d=await res.json();
    if(!res.ok){errEl.textContent='PIN unlock failed: '+d.error;return;}
    if(d.token){
      S.tokens[vid]=d.token;
      S.pinData[vid]={masterPassword:masterPw};
      const vd=await api.vaults(); S.vaults=vd.vaults;
      switchVault(vid);
      toast('Vault unlocked with PIN','success');
    }
  }catch(e){
    errEl.textContent='Incorrect PIN';
  }
}
function cancelPinUnlock(){
  document.getElementById('pin-unlock-form').style.display='none';
  document.getElementById('unlock-form').style.display='block';
  document.getElementById('pin-unlock-error').textContent='';
}

// ─── Entry Templates ──────────────────────────────────────────────────────────
const TEMPLATES={
  blank:{type:'login',title:'',username:'',password:'',url:'',notes:'',cat:'other'},
  login:{type:'login',title:'',username:'',password:'',url:'https://',notes:'',cat:'login'},
  email:{type:'login',title:'',username:'',password:'',url:'',notes:'',cat:'email',placeholder:{title:'e.g. Gmail',username:'user@example.com'}},
  banking:{type:'login',title:'',username:'',password:'',url:'',notes:'',cat:'banking',placeholder:{title:'e.g. Chase Bank',username:'Account number or login'}},
  social:{type:'login',title:'',username:'',password:'',url:'',notes:'',cat:'social',placeholder:{title:'e.g. Twitter/X',username:'@handle or email'}},
  wifi:{type:'note',title:'',username:'Network Name (SSID)',password:'',url:'',notes:'',cat:'other',placeholder:{title:'e.g. Home Wi-Fi',username:'Network name'}},
  license:{type:'login',title:'',username:'',password:'',url:'',notes:'License key:\nOrder number:\nRegistered email:',cat:'other',placeholder:{title:'e.g. Adobe Creative Cloud'}},
  apikey:{type:'note',title:'',username:'Service',password:'API Key / Token',url:'',notes:'',cat:'work',placeholder:{title:'e.g. GitHub API Key'}},
  note:{type:'note',title:'',username:'',password:'',url:'',notes:'',cat:'other'},
};
function openAddEntry(){
  openModal('templates-modal');
}

function useTemplate(name){
  closeModal('templates-modal');
  const tpl=TEMPLATES[name]||TEMPLATES.blank;
  S.editId=null;
  document.getElementById('modal-title').textContent='Add Entry';
  const ph=tpl.placeholder||{};
  document.getElementById('f-title').value=tpl.title||'';
  document.getElementById('f-title').placeholder=ph.title||'e.g. GitHub';
  document.getElementById('f-username').value=tpl.username||'';
  document.getElementById('f-username').placeholder=ph.username||'username@example.com';
  document.getElementById('f-password').value=tpl.password||'';
  document.getElementById('f-url').value=tpl.url||'';
  document.getElementById('f-notes').value=tpl.notes||'';
  const ft=document.getElementById('f-totp'); if(ft) ft.value='';
  const fe=document.getElementById('f-expiry'); if(fe) fe.value='';
  document.getElementById('f-fav').checked=false;
  setEntryType(tpl.type||'login');
  const defaultCat=tpl.cat||'other';
  renderCatChips([defaultCat]);
  document.getElementById('str-bar').style.width='0';
  document.getElementById('str-label').textContent='';
  openModal('entry-modal');
  setTimeout(()=>document.getElementById('f-title').focus(),100);
}

// ─── Entry Type (Login vs Secure Note) ────────────────────────────────────────
function setEntryType(type){
  document.getElementById('f-entry-type').value=type;
  const loginFields=['f-username','f-password','f-url','f-totp','f-expiry'];
  const isNote=(type==='note');
  // Toggle field rows by finding the closest .form-row ancestor
  loginFields.forEach(id=>{
    const el=document.getElementById(id);
    if(!el) return;
    const row=el.closest('.form-row')||el.closest('.form-row, .pw-row')?.closest('.form-row');
    // Walk up to find .form-row
    let node=el.parentNode;
    while(node&&!node.classList.contains('form-row')) node=node.parentNode;
    if(node) node.style.display=isNote?'none':'';
  });
  // Expand notes area for secure note
  const notesEl=document.getElementById('f-notes');
  if(notesEl) notesEl.style.minHeight=isNote?'140px':'80px';
  // Update type buttons
  document.getElementById('entry-type-login').classList.toggle('active',!isNote);
  document.getElementById('entry-type-note').classList.toggle('active',isNote);
}

// ─── URL Open button in detail ────────────────────────────────────────────────
function openEntryUrl(url){
  if(!url) return;
  const u=url.startsWith('http')?url:'https://'+url;
  window.open(u,'_blank');
}

// ─── WebAuthn / Security Key ──────────────────────────────────────────────────
function _b64url(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function _fromB64url(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4) s+='=';
  return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer;
}

async function doWebAuthnRegisterSetup(vaultId){
  const errEl=document.getElementById('twofa-webauthn-err'); if(errEl) errEl.textContent='';
  try{
    const opts=await api.webauthnRegisterBegin(vaultId);
    const cred=await navigator.credentials.create({publicKey:{
      challenge:_fromB64url(opts.challenge),
      rp:opts.rp,
      user:{id:new TextEncoder().encode(opts.user.id).buffer,name:opts.user.name,displayName:opts.user.displayName},
      pubKeyCredParams:opts.pubKeyCredParams,
      timeout:opts.timeout,
      attestation:opts.attestation||'none',
      authenticatorSelection:opts.authenticatorSelection||{}
    }});
    const r=cred.response;
    await api.webauthnRegisterFinish(vaultId,{
      id:cred.id, rawId:_b64url(cred.rawId),
      response:{
        clientDataJSON:_b64url(r.clientDataJSON),
        attestationObject:_b64url(r.attestationObject)
      }
    });
    toast('Security key registered!','success');
    return true;
  }catch(e){
    const msg=e.name==='NotAllowedError'?'Key tap cancelled or timed out':e.message;
    if(errEl) errEl.textContent=msg;
    toast('Security key registration failed: '+msg,'error');
    return false;
  }
}

async function selectTwofaWebAuthn(){
  const vid=S._2faVaultId||S.activeVault;
  if(!navigator.credentials){
    toast('Your browser does not support WebAuthn security keys','error'); return;
  }
  document.getElementById('twofa-type-picker').style.display='none';
  document.getElementById('twofa-webauthn-setup').style.display='';
  document.getElementById('twofa-webauthn-err').textContent='';
  const footer=document.getElementById('twofa-modal-footer');
  if(footer) footer.innerHTML=
    '<button class="btn-secondary" onclick="open2FASetup(S._2faVaultId)">Back</button>'+
    '<button class="btn-save" onclick="doWebAuthnRegisterFlow()">Register Security Key</button>';
}
async function doWebAuthnRegisterFlow(){
  const vid=S._2faVaultId||S.activeVault;
  const btn=document.querySelector('#twofa-modal-footer .btn-save');
  if(btn){btn.textContent='Waiting for key...';btn.disabled=true;}
  const ok=await doWebAuthnRegisterSetup(vid);
  if(btn){btn.textContent='Register Security Key';btn.disabled=false;}
  if(ok){
    closeModal('twofa-setup-modal');
    if(S._newVaultId){
      // Vault creation context: go back to addvault-modal success state
      openModal('addvault-modal');
      const footer=document.getElementById('addvault-footer');
      if(footer) footer.innerHTML='<button class="btn-secondary" onclick="doAddVaultSkip2FA()">Done</button>';
      toast('Security key registered for new vault!','success');
    } else {
      // Settings context
      openModal('settings-modal'); render2FAStatus(S.activeVault||vid);
    }
  }
}

// WebAuthn during vault unlock
async function doWebAuthnVerify(){
  const vid=S.unlockVaultId; if(!vid) return;
  const errEl=document.getElementById('webauthn-error'); if(errEl) errEl.textContent='';
  const opts=S.pendingWebAuthnOpts; if(!opts){toast('No challenge available','error');return;}
  try{
    const assertion=await navigator.credentials.get({publicKey:{
      challenge:_fromB64url(opts.challenge),
      rpId:opts.rpId||'localhost',
      allowCredentials:(opts.allowCredentials||[]).map(c=>({...c,id:_fromB64url(c.id)})),
      timeout:opts.timeout||60000,
      userVerification:opts.userVerification||'preferred'
    }});
    const r=assertion.response;
    const body={
      password:S.pendingUnlockPw,
      webauthn_credential_id:assertion.id,
      webauthn_client_data_json:_b64url(r.clientDataJSON),
      webauthn_auth_data:_b64url(r.authenticatorData),
      webauthn_signature:_b64url(r.signature)
    };
    const res=await fetch('/api/vaults/'+vid+'/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await res.json();
    if(!res.ok){if(errEl) errEl.textContent=d.error||'Verification failed';return;}
    S.tokens[vid]=d.token; S.pendingUnlockPw=''; S.pendingWebAuthnOpts=null;
    storePinSession(vid,'');  // no password available here
    const vd=await api.vaults(); S.vaults=vd.vaults;
    toast('Vault unlocked','success');
    switchVault(vid);
  }catch(e){
    const msg=e.name==='NotAllowedError'?'Key tap cancelled or timed out':e.message;
    if(errEl) errEl.textContent=msg;
  }
}
function cancelWebAuthn(){
  S.pendingWebAuthnOpts=null; S.pendingUnlockPw='';
  document.getElementById('webauthn-form').style.display='none';
  document.getElementById('unlock-form').style.display='block';
  const e=document.getElementById('webauthn-error'); if(e) e.textContent='';
}

// Handle addvault webauthn selection
async function selectTwofaMethodWebAuthn_Vault(){
  const vid=S._newVaultId; if(!vid) return;
  const footer=document.getElementById('addvault-footer');
  document.getElementById('addvault-step2-content').innerHTML=
    '<div class="info-box" style="margin-bottom:14px">&#128273; Click Register and touch your security key when prompted.</div>'+
    '<div id="addvault-webauthn-err" style="color:var(--red);font-size:12px;min-height:16px"></div>';
  if(footer) footer.innerHTML=
    '<button class="btn-secondary" onclick="doAddVaultSetup2FA()">Back</button>'+
    '<button class="btn-save" onclick="doAddVaultRegisterWebAuthn()">Register Security Key</button>';
}
async function doAddVaultRegisterWebAuthn(){
  const vid=S._newVaultId; if(!vid) return;
  const btn=document.querySelector('#addvault-footer .btn-save');
  if(btn){btn.textContent='Waiting for key...';btn.disabled=true;}
  const ok=await doWebAuthnRegisterSetup(vid);
  if(btn){btn.textContent='Register Security Key';btn.disabled=false;}
  if(ok){closeModal('addvault-modal');await switchVault(vid);toast('Vault created with security key 2FA!','success');}
}


// ─── Accent color presets ──────────────────────────────────────────────────────
const ACCENT_PRESETS = [
  {name:'Purple', accent:'#8b5cf6', glow:'rgba(139,92,246,0.25)'},
  {name:'Blue',   accent:'#3b82f6', glow:'rgba(59,130,246,0.25)'},
  {name:'Cyan',   accent:'#22d3ee', glow:'rgba(34,211,238,0.25)'},
  {name:'Green',  accent:'#10b981', glow:'rgba(16,185,129,0.25)'},
  {name:'Orange', accent:'#f97316', glow:'rgba(249,115,22,0.25)'},
  {name:'Pink',   accent:'#ec4899', glow:'rgba(236,72,153,0.25)'},
];
function applyAccentColor(preset){
  document.documentElement.style.setProperty('--accent', preset.accent);
  document.documentElement.style.setProperty('--accent-glow', preset.glow);
  localStorage.setItem('accent', JSON.stringify(preset));
}
function loadAccentColor(){
  try{
    const p=JSON.parse(localStorage.getItem('accent')||'null');
    if(p) applyAccentColor(p);
  }catch(e){}
}
function renderAccentSwatches(){
  const area=document.getElementById('accent-swatches'); if(!area) return;
  area.innerHTML='';
  const current=JSON.parse(localStorage.getItem('accent')||'null');
  ACCENT_PRESETS.forEach(p=>{
    const btn=document.createElement('button');
    btn.title=p.name;
    const isActive=current&&current.accent===p.accent;
    btn.style.cssText=`width:32px;height:32px;border-radius:50%;background:${p.accent};border:3px solid ${isActive?'var(--text)':'transparent'};cursor:pointer;transition:border .15s;`;
    btn.onclick=()=>{ applyAccentColor(p); renderAccentSwatches(); toast(p.name+' accent applied','success'); };
    area.appendChild(btn);
  });
}

// ─── Shared vault change detection ─────────────────────────────────────────────
function startSharedVaultPolling(){
  if(S._mtimeInterval) clearInterval(S._mtimeInterval);
  S._mtimeInterval = setInterval(async()=>{
    if(!S.activeVault) return;
    const vault = S.vaults.find(v=>v.id===S.activeVault);
    if(!vault || !vault.shared) return;
    try{
      const d = await api.vaultMtime(S.activeVault);
      const prev = S._lastMtime[S.activeVault];
      if(prev && d.mtime && d.mtime > prev + 1){
        S._lastMtime[S.activeVault] = d.mtime;
        toast('Shared vault updated on disk — reloading entries…','info');
        await loadEntries();
      } else if(d.mtime){
        S._lastMtime[S.activeVault] = d.mtime;
      }
    }catch(e){}
  }, 5000);
}
async function initVaultMtime(vid){
  try{
    const d = await api.vaultMtime(vid);
    if(d.mtime) S._lastMtime[vid] = d.mtime;
  }catch(e){}
}

// ─── Activity log ──────────────────────────────────────────────────────────────
const ACTION_LABELS = {
  unlock:'🔓 Vault unlocked', lock:'🔒 Vault locked',
  add_entry:'➕ Entry added', update_entry:'✏️ Entry updated', delete_entry:'🗑️ Entry deleted',
  merge:'🔀 Vault merged',
};
function fmtTime(ts){
  const d=new Date(ts*1000);
  return d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
async function renderActivityLog(){
  const area=document.getElementById('activity-log-area'); if(!area) return;
  area.innerHTML='<div style="color:var(--text-3);font-size:13px">Loading…</div>';
  try{
    const d=await api.vaultActivity(S.activeVault);
    if(!d.log||!d.log.length){ area.innerHTML='<div style="color:var(--text-3);font-size:13px;padding:8px 0">No activity recorded yet.</div>'; return; }
    area.innerHTML='';
    d.log.forEach(ev=>{
      const row=document.createElement('div');
      row.style.cssText='display:flex;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);font-size:13px;align-items:baseline';
      const ts=document.createElement('span'); ts.style.cssText='color:var(--text-3);white-space:nowrap;font-size:11px;min-width:150px'; ts.textContent=fmtTime(ev.ts);
      const act=document.createElement('span'); act.style.color='var(--text)';
      act.textContent=(ACTION_LABELS[ev.action]||ev.action)+(ev.detail?' — '+ev.detail:'');
      row.appendChild(ts); row.appendChild(act); area.appendChild(row);
    });
  }catch(e){ area.innerHTML='<div style="color:var(--text-3);font-size:13px">Could not load activity.</div>'; }
}

// ─── Vault merge ────────────────────────────────────────────────────────────────
function openMergeModal(){
  const sel=document.getElementById('merge-source-select');
  if(!sel) return;
  sel.innerHTML='<option value="">Select source vault…</option>';
  S.vaults.filter(v=>v.id!==S.activeVault).forEach(v=>{
    const o=document.createElement('option'); o.value=v.id; o.textContent=v.label; sel.appendChild(o);
  });
  document.getElementById('merge-pw').value='';
  document.getElementById('merge-result').textContent='';
  const btn=document.getElementById('merge-btn'); if(btn){ btn.textContent='Merge'; btn.disabled=false; }
  openModal('merge-modal');
}
async function doMergeVaults(){
  const src=document.getElementById('merge-source-select').value;
  const pw=document.getElementById('merge-pw').value;
  const res=document.getElementById('merge-result');
  const btn=document.getElementById('merge-btn');
  if(!src){ res.style.color='var(--red)'; res.textContent='Select a source vault.'; return; }
  if(!pw){ res.style.color='var(--red)'; res.textContent='Enter the source vault password.'; return; }
  btn.textContent='Merging…'; btn.disabled=true; res.textContent='';
  try{
    const d=await api.vaultMerge(S.activeVault,src,pw);
    res.style.color='var(--green)';
    res.textContent=`Done — added ${d.added} entr${d.added===1?'y':'ies'}, skipped ${d.skipped} duplicate${d.skipped===1?'':'s'}.`;
    btn.textContent='Merge'; btn.disabled=false;
    await loadEntries();
    toast(`Merged ${d.added} entries from vault`,'success');
  }catch(e){
    res.style.color='var(--red)'; res.textContent=e.message||'Merge failed';
    btn.textContent='Merge'; btn.disabled=false;
  }
}

async function init(){
  applyStoredTheme();
  const si=document.getElementById('search-input');
  if(si) si.addEventListener('input',()=>{S.q=si.value;applyFilter();});
  try{const vd=await api.vaults();S.vaults=vd.vaults;}
  catch(e){S.vaults=[{id:'local',label:'Personal',exists:false,path:''}];}
  showUnlockScreen(S.vaults[0]&&S.vaults[0].id);
  const pw=document.getElementById('unlock-pw');
  if(pw) pw.addEventListener('keydown',ev=>{if(ev.key==='Enter') doUnlock();});
}

init();



function fileIcon(mime) {
  if (!mime) return '📎';
  if (mime.startsWith('image/')) return '🖼️';
  if (mime.startsWith('video/')) return '🎬';
  if (mime.startsWith('audio/')) return '🎵';
  if (mime.includes('pdf'))  return '📄';
  if (mime.includes('zip') || mime.includes('compressed') || mime.includes('tar') || mime.includes('7z')) return '📦';
  if (mime.includes('word') || mime.includes('document')) return '📝';
  if (mime.includes('excel') || mime.includes('spreadsheet') || mime.includes('csv')) return '📊';
  if (mime.includes('presentation') || mime.includes('powerpoint')) return '📊';
  if (mime.startsWith('text/')) return '📄';
  if (mime.includes('json') || mime.includes('javascript') || mime.includes('html') || mime.includes('css')) return '💾';
  return '📎';
}

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function fmtDate(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, {month:'short', day:'numeric', year:'numeric'});
}






async function downloadFile(id, name) {
  try {
    const tok = getToken();
    const resp = await fetch(`/api/files/${id}/download`, {
      headers: {'X-Session-Token': tok}
    });
    if (!resp.ok) { toast('Download failed', 'error'); return; }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast(`Downloaded: ${name}`, 'success');
  } catch(e) { toast('Download failed: ' + e.message, 'error'); }
}







// ─── heartbeat — keeps the server alive while browser is open ─────────────────
setInterval(()=>{ fetch('/api/ping',{method:'POST'}).catch(()=>{}); }, 3000);
// Send first ping immediately on load
fetch('/api/ping',{method:'POST'}).catch(()=>{});

// ─── topbar file upload ────────────────────────────────────────────────────────
async function onTopbarFileUpload(event) {
  const files = Array.from(event.target.files||[]);
  event.target.value = '';
  if (!files.length) return;
  const cat = S.cat === 'all' || S.cat === 'favorites' ? 'other' : S.cat;
  let uploaded = 0;
  for (const file of files) {
    try {
      const fd = new FormData();
      fd.append('file', file, file.name);
      fd.append('category', cat);
      const resp = await fetch('/api/files', {
        method: 'POST',
        headers: {'X-Session-Token': getToken()},
        body: fd
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Upload failed');
      uploaded++;
    } catch(e) { toast('Failed: ' + file.name + ' — ' + e.message, 'error'); }
  }
  if (uploaded) {
    toast(uploaded === 1 ? 'File uploaded' : uploaded + ' files uploaded', 'success');
    await loadEntries();
  }
}

// ─── file entry editing ────────────────────────────────────────────────────────
function openFileEdit(id) {
  const e = S.entries.find(x => x.id === id); if (!e) return;
  S.editId = id;
  // Header
  const icon = document.getElementById('file-edit-icon');
  const titleDisp = document.getElementById('file-edit-title-display');
  if (icon) icon.textContent = fileIcon(e.file_mime || '');
  if (titleDisp) titleDisp.textContent = 'Edit File';
  // Fields
  document.getElementById('fe-title').value = e.title || '';
  document.getElementById('fe-notes').value = e.notes || '';
  document.getElementById('fe-fav').checked = !!e.favorite;
  // Meta info
  const meta = document.getElementById('fe-meta');
  if (meta) meta.textContent = [
    fmtSize(e.file_size || 0),
    e.file_mime || '',
    e.created_at ? ('Added ' + fmtDate(e.created_at)) : ''
  ].filter(Boolean).join(' · ');
  // Category chips (reuse existing chip logic with a different container id)
  const cats = e.categories && e.categories.length ? e.categories : (e.category ? [e.category] : ['other']);
  renderCatChipsInto('fe-cat-chips', cats);
  openModal('file-edit-modal');
  setTimeout(() => document.getElementById('fe-title')?.focus(), 100);
}

async function saveFileEdit() {
  const title = document.getElementById('fe-title').value.trim();
  if (!title) { toast('File name required', 'error'); return; }
  const notes   = document.getElementById('fe-notes').value;
  const fav     = document.getElementById('fe-fav').checked;
  // Get selected categories from fe-cat-chips
  const chips   = document.querySelectorAll('#fe-cat-chips .cat-chip.selected');
  const cats    = chips.length ? Array.from(chips).map(c => c.dataset.id) : ['other'];
  const cat     = cats[0] || 'other';
  try {
    const tok = getToken();
    const r = await fetch(`/api/entries/${S.editId}`, {
      method: 'PUT',
      headers: {'Content-Type':'application/json','X-Session-Token': tok},
      body: JSON.stringify({ title, notes, category: cat, categories: cats, favorite: fav })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Save failed');
    closeModal('file-edit-modal');
    toast('File updated', 'success');
    await loadEntries();
  } catch(e) { toast('Save failed: ' + e.message, 'error'); }
}

// Render category chips into an arbitrary container id
function renderCatChipsInto(containerId, selectedCats) {
  const container = document.getElementById(containerId); if (!container) return;
  container.innerHTML = '';
  S.categories.forEach(cat => {
    const chip = document.createElement('span');
    chip.className = 'cat-chip' + (selectedCats.includes(cat.id) ? ' selected' : '');
    chip.dataset.id = cat.id;
    if (selectedCats.includes(cat.id)) chip.style.background = cat.color || '#8b5cf6';
    chip.innerHTML = `<span>${cat.icon||'📁'}</span><span>${cat.label}</span>`;
    chip.onclick = () => {
      chip.classList.toggle('selected');
      chip.style.background = chip.classList.contains('selected') ? (cat.color||'#8b5cf6') : '';
    };
    container.appendChild(chip);
  });
}
