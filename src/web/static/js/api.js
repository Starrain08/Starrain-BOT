const API_TIMEOUT=15000;
const TOKEN_KEY='token';
const TOKEN_SALT_KEY='token_salt';
const TOKEN_HASH_KEY='token_hash';
const CSRFTokenKey='csrf_token';

class TokenManager{
constructor(){
this.useHashedToken=true;
this.originalToken=null;
this.tokenSalt=null;
this.tokenHash=null;
}

getToken(){
if(this.useHashedToken&&this.tokenHash){
return this.tokenHash;
}
return this.originalToken;
}

setOriginalToken(token,salt=null,hash=null){
this.originalToken=token;
if(salt)this.tokenSalt=salt;
if(hash)this.tokenHash=hash;
sessionStorage.setItem(TOKEN_KEY,token);
if(salt)sessionStorage.setItem(TOKEN_SALT_KEY,salt);
if(hash)sessionStorage.setItem(TOKEN_HASH_KEY,hash);
}

setUseHashedToken(use){
this.useHashedToken=use;
}

clear(){
this.originalToken=null;
this.tokenSalt=null;
this.tokenHash=null;
sessionStorage.removeItem(TOKEN_KEY);
sessionStorage.removeItem(TOKEN_SALT_KEY);
sessionStorage.removeItem(TOKEN_HASH_KEY);
}

loadFromStorage(){
const token=sessionStorage.getItem(TOKEN_KEY);
const salt=sessionStorage.getItem(TOKEN_SALT_KEY);
const hash=sessionStorage.getItem(TOKEN_HASH_KEY);
if(token){
this.originalToken=token;
if(salt)this.tokenSalt=salt;
if(hash)this.tokenHash=hash;
}
}
}

const tokenManager=new TokenManager();

const getCsrfToken=()=>{
return sessionStorage.getItem(CSRFTokenKey)||'';
};

const setCsrfToken=(token)=>{
sessionStorage.setItem(CSRFTokenKey,token);
};

const clearCsrfToken=()=>{
sessionStorage.removeItem(CSRFTokenKey);
};

const computeTokenHash=(token,salt)=>{
return new Promise((resolve)=>{
setTimeout(()=>{
try{
const encoder=new TextEncoder();
const data=encoder.encode(token+salt);
crypto.subtle.digest('SHA-256',data).then(hashBuffer=>{
const hashArray=Array.from(new Uint8Array(hashBuffer));
const hashHex=hashArray.map(b=>b.toString(16).padStart(2,'0')).join('');
resolve(hashHex);
});
}catch(e){
console.error('Token哈希计算失败:',e);
resolve(token);
}
},0);
});
};

const fetchWithTimeout=async(url,options={},timeout=API_TIMEOUT)=>{
const controller=new AbortController();
const timeoutId=setTimeout(()=>controller.abort(),timeout);
try{
const res=await fetch(url,{...options,signal:controller.signal});
const csrfHeader=res.headers.get('X-CSRF-Token');
if(csrfHeader){
setCsrfToken(csrfHeader);
}
clearTimeout(timeoutId);
return res;
}catch(e){
clearTimeout(timeoutId);
if(e.name==='AbortError')throw new Error('请求超时');
throw e;
}
};

const sanitizeError=(error)=>{
const safeErrors={
'请求超时':'请求超时，请稍后重试',
'未授权':'会话已过期，请重新登录',
'请求过于频繁':'请求过于频繁，请稍后重试',
'网络错误':'网络连接失败',
'缺少CSRF令牌':'安全验证失败，请刷新页面后重试',
'CSRF令牌无效或已过期':'会话已过期，请重新登录',
};
return safeErrors[error]||'操作失败，请稍后重试';
};

const api=async(url,options={},tokenValue,csrfTokenValue)=>{
const headers={'Content-Type':'application/json'};

if(tokenValue||tokenManager.getToken()){
const tokenToUse=tokenValue||tokenManager.getToken();
if(tokenToUse)headers['Authorization']=`Bearer ${tokenToUse}`;
}

if(csrfTokenValue){
headers['X-CSRF-Token']=csrfTokenValue;
}

const method=(options.method||'GET').toUpperCase();
if(method!=='GET'&&method!=='HEAD'&&method!=='OPTIONS'){
const csrf=csrfTokenValue||getCsrfToken();
if(!csrf){
throw new Error('缺少CSRF令牌');
}
headers['X-CSRF-Token']=csrf;
}

try{
const res=await fetchWithTimeout(url,{...options,headers});
const data=await res.json().catch(()=>({}));

if(res.status===401){
tokenManager.clear();
clearCsrfToken();
throw new Error('未授权');
}

if(res.status===403){
clearCsrfToken();
throw new Error(data.error||'CSRF令牌无效或已过期');
}

if(res.status===429){
throw new Error('请求过于频繁');
}

if(!res.ok){
throw new Error(data.error||'请求失败');
}

return data;
}catch(e){
if(e.message==='请求超时')throw new Error('请求超时');
if(e.name==='TypeError')throw new Error('网络错误');
throw e;
}
};

export{fetchWithTimeout,sanitizeError,api,API_TIMEOUT,getCsrfToken,setCsrfToken,clearCsrfToken,tokenManager,TOKEN_KEY,TOKEN_SALT_KEY,TOKEN_HASH_KEY,computeTokenHash};
