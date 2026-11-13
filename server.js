'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 8787);
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const STORE_FILE = path.join(DATA_DIR, 'auth-store.json');
const rooms = new Map();
const clients = new Map();
const users = new Map();
const sessions = new Map();
const verification = new Map();
const mime = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.svg':'image/svg+xml' };
fs.mkdirSync(DATA_DIR, { recursive: true });
try { const saved=JSON.parse(fs.readFileSync(STORE_FILE,'utf8')); for(const u of saved.users||[])users.set(u.email,u); for(const [t,v] of saved.sessions||[])if(v.expires>Date.now())sessions.set(t,v); } catch {}
function persistUsers(){fs.writeFileSync(STORE_FILE,JSON.stringify({users:[...users.values()],sessions:[...sessions.entries()]},null,2));}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')};}
function passwordMatches(password,u){const got=crypto.scryptSync(password,u.salt,64);const expected=Buffer.from(u.passwordHash,'hex');return expected.length===got.length&&crypto.timingSafeEqual(got,expected);}
function json(res,status,data){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});res.end(JSON.stringify(data));}
async function body(req){let raw='';for await(const chunk of req)raw+=chunk;if(raw.length>2_000_000)throw new Error('Слишком большой запрос');return raw?JSON.parse(raw):{};}
function bearer(req){const h=req.headers.authorization||'';return h.startsWith('Bearer ')?h.slice(7):'';}
function currentUser(req){const token=bearer(req);const s=sessions.get(token);if(!s||s.expires<Date.now()){if(s)sessions.delete(token);return null;}return users.get(s.email)||null;}
function publicUser(u){return {email:u.email,name:u.name||u.email.split('@')[0],status:u.status||'В сети',avatar:u.avatar||'',createdAt:u.createdAt};}
async function sendVerification(email,code,purpose='Подтверждение почты'){
  if(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS){
    const nodemailer=require('nodemailer');const transport=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:process.env.SMTP_SECURE==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
    await transport.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to:email,subject:`VoiceChat — ${purpose}`,text:`Ваш код: ${code}\nКод действует 10 минут. Если вы не запрашивали его, проигнорируйте письмо.`,html:`<div style="font-family:Arial;padding:24px"><h2>VoiceChat</h2><p>${purpose}</p><div style="font-size:30px;font-weight:bold;letter-spacing:8px">${code}</div><p>Код действует 10 минут.</p></div>`});
    return {sent:true};
  }
  console.log(`[DEV EMAIL] ${email} | ${purpose} | CODE: ${code}`);
  return {sent:false,devCode:process.env.NODE_ENV==='production'?undefined:code};
}
async function api(req,res,url){
  try{
    if(req.method==='POST'&&url.pathname==='/api/register'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||''),name=String(b.name||'').trim().slice(0,32);
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json(res,400,{error:'Укажи корректный email.'});
      if(password.length<8)return json(res,400,{error:'Пароль должен содержать минимум 8 символов.'});
      if(users.has(email)&&users.get(email).verified)return json(res,409,{error:'Аккаунт с такой почтой уже существует.'});
      const p=hashPassword(password);users.set(email,{email,...p,passwordHash:p.hash,name:name||email.split('@')[0],status:'В сети',avatar:'',verified:false,createdAt:Date.now()});persistUsers();
      const code=String(crypto.randomInt(100000,1000000));verification.set(email,{code,expires:Date.now()+600000,purpose:'verify'});const mail=await sendVerification(email,code);return json(res,200,{ok:true,message:'Код подтверждения отправлен на почту.',...(!mail.sent&&mail.devCode?{devCode:mail.devCode}:{})});
    }
    if(req.method==='POST'&&url.pathname==='/api/verify'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),code=String(b.code||'').trim(),v=verification.get(email),u=users.get(email);
      if(!u||!v||v.purpose!=='verify'||v.expires<Date.now()||v.code!==code)return json(res,400,{error:'Код неверный или срок его действия истёк.'});
      u.verified=true;verification.delete(email);persistUsers();const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{email,expires:Date.now()+30*86400000});persistUsers();return json(res,200,{ok:true,token,user:publicUser(u)});
    }
    if(req.method==='POST'&&url.pathname==='/api/login'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),u=users.get(email);
      if(!u||!passwordMatches(String(b.password||''),u))return json(res,401,{error:'Неверная почта или пароль.'});
      if(!u.verified)return json(res,403,{error:'Сначала подтверди почту. Используй повторную отправку кода.'});
      const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{email,expires:Date.now()+30*86400000});persistUsers();return json(res,200,{ok:true,token,user:publicUser(u)});
    }
    if(req.method==='POST'&&url.pathname==='/api/resend-code'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),u=users.get(email);if(!u||u.verified)return json(res,404,{error:'Незавершённая регистрация не найдена.'});
      const code=String(crypto.randomInt(100000,1000000));verification.set(email,{code,expires:Date.now()+600000,purpose:'verify'});const mail=await sendVerification(email,code);return json(res,200,{ok:true,message:'Новый код отправлен.',...(!mail.sent&&mail.devCode?{devCode:mail.devCode}:{})});
    }
    if(req.method==='POST'&&url.pathname==='/api/forgot-password'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),u=users.get(email);if(!u||!u.verified)return json(res,200,{ok:true,message:'Если аккаунт существует, код восстановления отправлен.'});
      const code=String(crypto.randomInt(100000,1000000));verification.set(email,{code,expires:Date.now()+600000,purpose:'reset'});const mail=await sendVerification(email,code,'Восстановление пароля');return json(res,200,{ok:true,message:'Код восстановления отправлен.',...(!mail.sent&&mail.devCode?{devCode:mail.devCode}:{})});
    }
    if(req.method==='POST'&&url.pathname==='/api/reset-password'){
      const b=await body(req),email=String(b.email||'').trim().toLowerCase(),code=String(b.code||'').trim(),password=String(b.password||''),u=users.get(email),v=verification.get(email);
      if(password.length<8)return json(res,400,{error:'Новый пароль должен содержать минимум 8 символов.'});
      if(!u||!v||v.purpose!=='reset'||v.expires<Date.now()||v.code!==code)return json(res,400,{error:'Код неверный или срок его действия истёк.'});
      const p=hashPassword(password);u.salt=p.salt;u.passwordHash=p.hash;verification.delete(email);for(const [t,s] of sessions)if(s.email===email)sessions.delete(t);persistUsers();return json(res,200,{ok:true,message:'Пароль изменён. Теперь войди с новым паролем.'});
    }
    if(req.method==='GET'&&url.pathname==='/api/me'){const u=currentUser(req);return u?json(res,200,{user:publicUser(u)}):json(res,401,{error:'Сессия истекла.'});}
    if(req.method==='POST'&&url.pathname==='/api/profile'){
      const u=currentUser(req);if(!u)return json(res,401,{error:'Нужно войти в аккаунт.'});const b=await body(req);u.name=String(b.name||u.name).trim().slice(0,32)||u.name;u.status=String(b.status||'В сети').trim().slice(0,48);u.avatar=String(b.avatar||'').slice(0,1_500_000);persistUsers();return json(res,200,{user:publicUser(u)});
    }
    if(req.method==='POST'&&url.pathname==='/api/logout'){const t=bearer(req);sessions.delete(t);persistUsers();return json(res,200,{ok:true});}
    return json(res,404,{error:'Не найдено.'});
  }catch(e){console.error('API error:',e);return json(res,500,{error:'Ошибка сервера. Проверь настройки почты и логи.'});}
}
function send(ws,obj){if(ws.readyState!==1)return;const data=Buffer.from(JSON.stringify(obj));let head;if(data.length<126)head=Buffer.from([0x81,data.length]);else if(data.length<65536){head=Buffer.alloc(4);head[0]=0x81;head[1]=126;head.writeUInt16BE(data.length,2);}else{head=Buffer.alloc(10);head[0]=0x81;head[1]=127;head.writeBigUInt64BE(BigInt(data.length),2);}ws.socket.write(Buffer.concat([head,data]));}
function broadcastRoom(room,message,exceptId){for(const id of room.members){const c=clients.get(id);if(c&&id!==exceptId)send(c.ws,message);}}
function roomList(){return [...rooms.values()].map(r=>({id:r.id,name:r.name,count:r.members.size,locked:false}));}
function publishRooms(){for(const c of clients.values())send(c.ws,{type:'rooms',rooms:roomList()});}
function cleanName(s,fallback){return String(s||fallback).trim().slice(0,32)||fallback;}
function leave(c){if(!c.roomId)return;const room=rooms.get(c.roomId);if(!room){c.roomId=null;return;}room.members.delete(c.id);broadcastRoom(room,{type:'peer-left',peerId:c.id});c.roomId=null;if(room.id!=='lobby'&&room.members.size===0)rooms.delete(room.id);publishRooms();}
function join(c,roomId){const room=rooms.get(roomId);if(!room)return send(c.ws,{type:'error',message:'Комната не найдена или уже закрыта.'});if(c.roomId===roomId)return;leave(c);c.roomId=roomId;room.members.add(c.id);const peers=[];for(const id of room.members){if(id===c.id)continue;const p=clients.get(id);if(p)peers.push({id:p.id,name:p.name,mic:p.mic,avatar:p.avatar,status:p.status});}send(c.ws,{type:'joined',room:{id:room.id,name:room.name},peers});send(c.ws,{type:'chat-history',messages:room.chat.slice(-80)});broadcastRoom(room,{type:'peer-joined',peer:{id:c.id,name:c.name,mic:c.mic,avatar:c.avatar,status:c.status}},c.id);publishRooms();}
function handle(c,m){switch(m.type){case'hello':c.name=cleanName(m.name,c.account.name);c.avatar=m.avatar||c.account.avatar||'';c.status=cleanName(m.status,c.account.status||'В сети');send(c.ws,{type:'welcome',id:c.id,rooms:roomList(),user:publicUser(c.account)});break;case'list-rooms':send(c.ws,{type:'rooms',rooms:roomList()});break;case'create-room':{const name=cleanName(m.name,'Новая комната');const id=crypto.randomBytes(4).toString('hex').toUpperCase();rooms.set(id,{id,name,members:new Set(),chat:[]});publishRooms();join(c,id);break;}case'join-room':join(c,String(m.roomId||'').toUpperCase()==='LOBBY'?'lobby':String(m.roomId||'').toUpperCase());break;case'leave-room':leave(c);send(c.ws,{type:'left-room'});break;case'profile':c.name=cleanName(m.name,c.name);c.avatar=m.avatar||'';c.status=cleanName(m.status,'В сети');c.account.name=c.name;c.account.avatar=c.avatar;c.account.status=c.status;persistUsers();if(c.roomId){const r=rooms.get(c.roomId);if(r)broadcastRoom(r,{type:'peer-profile',peer:{id:c.id,name:c.name,avatar:c.avatar,status:c.status}},c.id);}break;case'mic-state':c.mic=!!m.enabled;if(c.roomId){const r=rooms.get(c.roomId);if(r)broadcastRoom(r,{type:'peer-mic',peerId:c.id,enabled:c.mic},c.id);}break;case'signal':{const target=clients.get(String(m.to));if(target&&c.roomId&&target.roomId===c.roomId)send(target.ws,{type:'signal',from:c.id,signal:m.signal});break;}case'chat':{const r=rooms.get(c.roomId);if(r){const text=String(m.text||'').trim().slice(0,500);if(text){const msg={id:crypto.randomUUID(),from:c.id,name:c.name,text,at:Date.now(),reactions:{}};r.chat.push(msg);if(r.chat.length>200)r.chat.shift();broadcastRoom(r,{type:'chat',message:msg},null);}}break;}case'react':{const r=rooms.get(c.roomId);if(!r)break;const msg=r.chat.find(x=>x.id===m.messageId);if(!msg)break;const emoji=String(m.emoji||'').slice(0,8);if(!emoji)break;msg.reactions=msg.reactions||{};msg.reactions[emoji]=msg.reactions[emoji]||[];const arr=msg.reactions[emoji],idx=arr.indexOf(c.id);if(idx>=0)arr.splice(idx,1);else arr.push(c.id);if(!arr.length)delete msg.reactions[emoji];broadcastRoom(r,{type:'reaction',messageId:msg.id,reactions:msg.reactions},null);break;}}}

const server=http.createServer(async(req,res)=>{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/'))return api(req,res,url);let pathname=decodeURIComponent(url.pathname);if(pathname==='/health'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({ok:true,users:users.size,online:clients.size,rooms:rooms.size}));}if(pathname==='/invite')pathname='/';const file=path.join(PUBLIC,pathname==='/'?'index.html':pathname.replace(/^\/+/,''));if(!file.startsWith(PUBLIC)){res.writeHead(403);return res.end('Forbidden');}fs.readFile(file,(err,data)=>{if(err){res.writeHead(404);return res.end('Not found');}res.writeHead(200,{'content-type':mime[path.extname(file)]||'application/octet-stream','cache-control':'no-store'});res.end(data);});});
server.on('upgrade',(req,socket)=>{const url=new URL(req.url,'http://localhost');if(url.pathname!=='/ws'){socket.destroy();return;}const token=url.searchParams.get('token')||'',session=sessions.get(token);if(!session||session.expires<Date.now()||!users.has(session.email)){socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');socket.destroy();return;}const account=users.get(session.email);const key=req.headers['sec-websocket-key'];if(!key){socket.destroy();return;}const accept=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');const ws={socket,readyState:1,buffer:Buffer.alloc(0)};const c={id:crypto.randomUUID(),ws,name:account.name||'Гость',roomId:null,mic:true,account};clients.set(c.id,c);socket.on('data',chunk=>{ws.buffer=Buffer.concat([ws.buffer,chunk]);while(ws.buffer.length>=2){const b0=ws.buffer[0],b1=ws.buffer[1];let len=b1&127,off=2;if(len===126){if(ws.buffer.length<4)break;len=ws.buffer.readUInt16BE(2);off=4;}else if(len===127){if(ws.buffer.length<10)break;const n=ws.buffer.readBigUInt64BE(2);if(n>1_000_000n){socket.destroy();return;}len=Number(n);off=10;}const masked=!!(b1&128);if(masked)off+=4;if(ws.buffer.length<off+len)break;let payload=ws.buffer.subarray(off,off+len);if(masked){const mask=ws.buffer.subarray(off-4,off);payload=Buffer.from(payload);for(let i=0;i<payload.length;i++)payload[i]^=mask[i%4];}ws.buffer=ws.buffer.subarray(off+len);if((b0&15)===8){socket.end();return;}if((b0&15)===9){socket.write(Buffer.from([0x8A,0]));continue;}if((b0&15)===1){try{handle(c,JSON.parse(payload.toString('utf8')));}catch(e){send(ws,{type:'error',message:'Некорректное сообщение.'});}}}});const disconnected=()=>{if(!clients.has(c.id))return;leave(c);clients.delete(c.id);};socket.on('close',disconnected);socket.on('error',disconnected);});

server.listen(PORT,'0.0.0.0',()=>console.log(`VoiceChat Web запущен: http://localhost:${PORT}`));
