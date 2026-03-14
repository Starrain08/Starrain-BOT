import{fetchWithTimeout,sanitizeError,setCsrfToken,clearCsrfToken,tokenManager,TOKEN_SALT_KEY,TOKEN_HASH_KEY}from'./api.js';

const getToken=()=>{
tokenManager.loadFromStorage();
return tokenManager.getToken();
};

const setToken=(t, salt=null, hash=null)=>{
tokenManager.setOriginalToken(t,salt,hash);
};

const clearToken=()=>{
tokenManager.clear();
};

const login=async(username,password,onSuccess,onError)=>{
try{
const res=await fetchWithTimeout('/api/login',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({username,password})
},10000);

const csrfHeader=res.headers.get('X-CSRF-Token');
const saltHeader=res.headers.get('X-Auth-Token-Salt');
const hashHeader=res.headers.get('X-Auth-Token-Hash');

if(csrfHeader){
setCsrfToken(csrfHeader);
}

const data=await res.json().catch(()=>({}));

if(data.success){
const token=data.token;
const salt=saltHeader||data.token_salt;
const hash=hashHeader||data.token_hash;

setToken(token,salt,hash);

onSuccess(token);

// 登录信息
console.log('登录成功，Token安全模式:',data.security_info?.token_hash_enabled?'已启用':'未启用');
if(data.security_info?.hint){
console.log('安全提示:',data.security_info.hint);
}
}else{
onError(data.error||'登录失败');
}
}catch(e){
onError(sanitizeError(e.message));
}
};

const logout=async()=>{
try{
const token=getToken();
await fetchWithTimeout('/api/logout',{
method:'POST',
headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'}
},5000);
}catch(e){}
clearToken();
clearCsrfToken();
};

const checkAuth=async(token)=>{
if(!token)return false;
try{
const res=await fetchWithTimeout('/api/status',{
headers:{'Authorization':`Bearer ${token}`}
});
return res.ok;
}catch(e){
return false;
}
};

export{getToken,setToken,clearToken,login,logout,checkAuth};
