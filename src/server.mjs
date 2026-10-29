import http from 'node:http';import fs from 'node:fs';import {randomBytes,generateKeyPairSync,createPrivateKey,createPublicKey} from 'node:crypto';import {Gateway} from './core.mjs';
fs.mkdirSync('data',{recursive:true,mode:0o700});
if(!fs.existsSync('data/key.pem')){const k=generateKeyPairSync('ed25519');fs.writeFileSync('data/key.pem',k.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600})}
if(!fs.existsSync('data/access.json'))fs.writeFileSync('data/access.json',JSON.stringify({agent:randomBytes(32).toString('hex'),reviewer:randomBytes(32).toString('hex')},null,2),{mode:0o600});
const access=JSON.parse(fs.readFileSync('data/access.json'));const privateKey=createPrivateKey(fs.readFileSync('data/key.pem')),g=new Gateway('data/demo.sqlite',{privateKey,publicKey:createPublicKey(privateKey)});const html=fs.readFileSync('public/index.html');
const server=http.createServer(async(req,res)=>{res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'");res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Cache-Control','no-store');const send=(s,b)=>{res.writeHead(s,{'Content-Type':'application/json'});res.end(JSON.stringify(b))};
if(req.headers.host!==`127.0.0.1:${server.address().port}`){send(403,{error:'Use loopback address'});return}
if(req.method==='GET'&&req.url==='/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(html);return}
if(req.method==='GET'&&req.url==='/public-key'){send(200,{pem:g.keys.publicKey.export({format:'pem',type:'spki'})});return}
const token=req.headers.authorization?.replace(/^Bearer /,'');const role=Object.keys(access).find(k=>access[k]===token);if(!role){send(401,{error:'Valid demo token required'});return}
if(req.headers.origin&&req.headers.origin!==`http://${req.headers.host}`){send(403,{error:'Origin rejected'});return}
try{let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>16000){send(413,{error:'Request too large'});return}}const body=raw?JSON.parse(raw):{};
if(req.method==='GET'&&req.url==='/api/state'){send(200,g.snapshot('demo'));return}
if(req.method==='POST'&&req.url==='/api/verify'){send(200,{valid:g.verify(body)});return}
if(req.method==='POST'&&req.url==='/api/authorize'&&role==='agent'){send(200,g.authorize('demo',req.headers['idempotency-key'],body));return}
const m=req.url.match(/^\/api\/requests\/([\w-]+)\/(approve|reject|execute)$/);if(req.method==='POST'&&m){const [,id,action]=m;if((action==='execute'&&role!=='agent')||(action!=='execute'&&role!=='reviewer')){send(403,{error:'Role cannot perform this action'});return}send(200,action==='execute'?g.execute('demo',id):g.approve('demo',id,action==='approve'));return}send(404,{error:'Unknown route or role'})}catch(e){send(400,{error:e.message})}});
server.listen(Number(process.env.PORT||8080),'127.0.0.1',()=>console.log(`AgentTrust simulation: http://127.0.0.1:${server.address().port}\nUse the agent/reviewer tokens from data/access.json. Keep this local.`));
