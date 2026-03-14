import{api,sanitizeError,getCsrfToken}from'./api.js';

const fetchStatus=async(token)=>{
try{
return await api('/api/status',{},token);
}catch(e){return null;}
};

const fetchPlugins=async(token)=>{
try{
return(await api('/api/plugins',{},token)).plugins||[];
}catch(e){return[];}
};

const enablePlugin=async(token,name)=>{
await api('/api/plugins/enable',{method:'POST',body:JSON.stringify({plugin_name:name})},token);
};

const disablePlugin=async(token,name)=>{
await api('/api/plugins/disable',{method:'POST',body:JSON.stringify({plugin_name:name})},token);
};

const reloadPlugin=async(token,name)=>{
await api('/api/plugins/reload',{method:'POST',body:JSON.stringify({plugin_name:name})},token);
};

const fetchPermissions=async(token)=>{
try{
return await api('/api/permissions/admins',{},token);
}catch(e){return{admins:[],owners:[],developers:[]};}
};

const addAdmin=async(token,qq)=>{
await api('/api/permissions/admins/add',{method:'POST',body:JSON.stringify({qq})},token);
};

const removeAdmin=async(token,qq)=>{
await api('/api/permissions/admins/remove',{method:'POST',body:JSON.stringify({qq})},token);
};

const addOwner=async(token,qq)=>{
await api('/api/permissions/owners/add',{method:'POST',body:JSON.stringify({qq})},token);
};

const removeOwner=async(token,qq)=>{
await api('/api/permissions/owners/remove',{method:'POST',body:JSON.stringify({qq})},token);
};

const addDeveloper=async(token,qq)=>{
await api('/api/permissions/developers/add',{method:'POST',body:JSON.stringify({qq})},token);
};

const removeDeveloper=async(token,qq)=>{
await api('/api/permissions/developers/remove',{method:'POST',body:JSON.stringify({qq})},token);
};

const fetchBlacklist=async(token)=>{
try{
return(await api('/api/blacklist',{},token)).groups||[];
}catch(e){return[];}
};

const addBlacklist=async(token,group_id)=>{
await api('/api/blacklist/add',{method:'POST',body:JSON.stringify({group_id})},token);
};

const removeBlacklist=async(token,group_id)=>{
await api('/api/blacklist/remove',{method:'POST',body:JSON.stringify({group_id})},token);
};

const fetchLogs=async(token,lines=200)=>{
try{
return(await api(`/api/logs?lines=${lines}`,{},token)).logs||[];
}catch(e){return[];}
};

const fetchGroups=async(token)=>{
try{
return(await api('/api/groups',{},token)).groups||[];
}catch(e){return[];}
};

const fetchFriends=async(token)=>{
try{
return(await api('/api/friends',{},token)).friends||[];
}catch(e){return[];}
};

const sendMessage=async(token,msgType,userId,groupId,message)=>{
await api('/api/message/send',{
method:'POST',
body:JSON.stringify({
message_type:msgType,
user_id:userId,
group_id:groupId,
message
})
},token);
};

const restartBot=async(token)=>{
await api('/api/system/restart',{method:'POST',body:JSON.stringify({confirm:true})},token);
};

const shutdownBot=async(token)=>{
await api('/api/system/shutdown',{method:'POST',body:JSON.stringify({confirm:true})},token);
};

export{
fetchStatus,fetchPlugins,enablePlugin,disablePlugin,reloadPlugin,
fetchPermissions,addAdmin,removeAdmin,addOwner,removeOwner,addDeveloper,removeDeveloper,
fetchBlacklist,addBlacklist,removeBlacklist,
fetchLogs,fetchGroups,fetchFriends,sendMessage,
restartBot,shutdownBot,sanitizeError
};
