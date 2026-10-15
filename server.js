const http=require('http'),https=require('https'),net=require('net'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=process.pkg?path.dirname(process.execPath):__dirname,DATA=path.join(ROOT,'data'),CACHE=path.join(DATA,'cache'),PORT=Number(process.env.PROXY_PORT||8080),DASH=Number(process.env.DASHBOARD_PORT||8787);
for(const d of [DATA,CACHE])fs.mkdirSync(d,{recursive:true});
const files={config:path.join(DATA,'config.json'),blocked:path.join(DATA,'blocked-hosts.json'),log:path.join(DATA,'proxy.log')};
function read(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{return fallback}}
function write(file,v){fs.writeFileSync(file,JSON.stringify(v,null,2))}
if(!fs.existsSync(files.config))write(files.config,{cacheEnabled:true,maxObjectBytes:2000000});
if(!fs.existsSync(files.blocked))write(files.blocked,[]);
const stats={requests:0,hits:0,misses:0,bypass:0,blocked:0,bytesIn:0,bytesOut:0,recent:[]};
function log(type,detail={}){const item={time:new Date().toISOString(),type,...detail};stats.recent.unshift(item);stats.recent=stats.recent.slice(0,100);fs.appendFile(files.log,JSON.stringify(item)+'\n',()=>{})}
function isBlocked(host){const list=read(files.blocked,[]),h=String(host||'').toLowerCase();return list.some(x=>h===x||h.endsWith('.'+x))}
function sendJson(res,code,data){res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});res.end(JSON.stringify(data))}
const dashboard=http.createServer((req,res)=>{const u=new URL(req.url,`http://127.0.0.1:${DASH}`);
if(u.pathname==='/api/status')return sendJson(res,200,{ok:true,name:'CEOAI Juwet',version:'0.1.0',proxyPort:PORT,dashboardPort:DASH,httpsMode:'CONNECT tunnel',stats,cacheObjects:fs.readdirSync(CACHE).filter(x=>x.endsWith('.json')).length});
if(u.pathname==='/api/blocked'&&req.method==='GET')return sendJson(res,200,read(files.blocked,[]));
if(u.pathname==='/api/blocked'&&req.method==='POST'){let body='';req.on('data',c=>body+=c);req.on('end',()=>{try{const host=String(JSON.parse(body).host||'').trim().toLowerCase();if(!host||/[^a-z0-9.-]/.test(host))return sendJson(res,400,{ok:false,error:'Host tidak valid'});const list=read(files.blocked,[]);if(!list.includes(host))list.push(host);write(files.blocked,list);log('filter-add',{host});sendJson(res,200,{ok:true,blocked:list})}catch{sendJson(res,400,{ok:false,error:'JSON tidak valid'})}});return}
if(u.pathname.startsWith('/api/blocked/')&&req.method==='DELETE'){const host=decodeURIComponent(u.pathname.slice(14)).toLowerCase(),list=read(files.blocked,[]).filter(x=>x!==host);write(files.blocked,list);log('filter-remove',{host});return sendJson(res,200,{ok:true,blocked:list})}
if(u.pathname==='/api/cache/purge'&&req.method==='POST'){for(const f of fs.readdirSync(CACHE))if(f.endsWith('.json'))try{fs.unlinkSync(path.join(CACHE,f))}catch{}log('cache-purge');return sendJson(res,200,{ok:true})}
if(u.pathname==='/api/logs'){let rows=[];try{rows=fs.readFileSync(files.log,'utf8').trim().split(/\r?\n/).filter(Boolean).slice(-200).reverse().map(JSON.parse)}catch{}return sendJson(res,200,rows)}
if(u.pathname==='/logo.svg'){res.writeHead(200,{'content-type':'image/svg+xml'});return fs.createReadStream(path.join(ROOT,'public','logo.svg')).pipe(res)}
if(u.pathname==='/'||u.pathname==='/index.html'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});return fs.createReadStream(path.join(ROOT,'public','index.html')).pipe(res)}
res.writeHead(404);res.end('Not found')});
dashboard.listen(DASH,'127.0.0.1',()=>console.log('CEOAI Juwet dashboard http://127.0.0.1:'+DASH));
function proxyRequest(req,res){stats.requests++;let target;try{target=new URL(req.url);if(!target.hostname)throw Error()}catch{res.writeHead(400);res.end('Proxy expects absolute URL');return}
const host=target.hostname.toLowerCase();if(isBlocked(host)){stats.blocked++;log('blocked',{host,url:req.url});res.writeHead(403);res.end('Blocked by CEOAI Juwet');return}
const config=read(files.config,{cacheEnabled:true,maxObjectBytes:2000000}),canCache=req.method==='GET'&&config.cacheEnabled!==false&&target.protocol==='http:',key=crypto.createHash('sha256').update(target.href).digest('hex'),cf=path.join(CACHE,key+'.json');
if(canCache){try{const cached=JSON.parse(fs.readFileSync(cf,'utf8'));if(cached.expiresAt>Date.now()){stats.hits++;stats.bytesOut+=Buffer.from(cached.body,'base64').length;log('HIT',{host,url:target.href,statusCode:cached.statusCode});res.writeHead(cached.statusCode,{...cached.headers,'x-ceoai-cache':'HIT'});res.end(Buffer.from(cached.body,'base64'));return}}catch{}stats.misses++}else stats.bypass++;
const transport=target.protocol==='https:'?https:http,headers={...req.headers,host:target.host};delete headers['proxy-connection'];
const upstream=transport.request(target,{method:req.method,headers,timeout:20000},up=>{const chunks=[];let size=0;up.on('data',chunk=>{stats.bytesIn+=chunk.length;size+=chunk.length;if(canCache&&size<=Number(config.maxObjectBytes||2000000))chunks.push(chunk)});up.on('end',()=>{if(canCache&&size<=Number(config.maxObjectBytes||2000000)&&up.statusCode===200&&!up.headers['set-cookie']&&!/private|no-store/i.test(up.headers['cache-control']||'')){const ttl=Math.min(3600,Math.max(30,Number((up.headers['cache-control']||'').match(/max-age=(\d+)/)?.[1]||120)));try{fs.writeFileSync(cf,JSON.stringify({statusCode:up.statusCode,headers:up.headers,body:Buffer.concat(chunks).toString('base64'),expiresAt:Date.now()+ttl*1000}))}catch{}}
log(canCache?'MISS':'BYPASS',{host,url:target.href,statusCode:up.statusCode,bytes:size});res.writeHead(up.statusCode,{...up.headers,'x-ceoai-cache':canCache?'MISS':'BYPASS'});up.pipe(res)})});
upstream.on('timeout',()=>upstream.destroy(Error('upstream timeout')));upstream.on('error',e=>{log('upstream-error',{host,error:e.message});if(!res.headersSent){res.writeHead(502,{'content-type':'text/plain'});res.end('Upstream error: '+e.message)}else res.destroy()});req.pipe(upstream)}
const proxy=http.createServer(proxyRequest);
proxy.on('connect',(req,client,head)=>{stats.requests++;const [host,portText]=req.url.split(':'),port=Number(portText||443);if(isBlocked(host)){stats.blocked++;log('blocked-connect',{host});client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return}const upstream=net.connect(port,host,()=>{client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: CEOAI-Juwet\r\n\r\n');if(head?.length)upstream.write(head);upstream.pipe(client);client.pipe(upstream);log('HTTPS-TUNNEL',{host,port})});upstream.setTimeout(20000,()=>upstream.destroy(Error('connect timeout')));upstream.on('error',e=>{log('connect-error',{host,error:e.message});if(!client.destroyed)client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')});client.on('error',()=>upstream.destroy())});
proxy.listen(PORT,'0.0.0.0',()=>console.log('CEOAI Juwet proxy listening on '+PORT));
function stop(){proxy.close();dashboard.close();process.exit(0)}process.on('SIGINT',stop);process.on('SIGTERM',stop);
