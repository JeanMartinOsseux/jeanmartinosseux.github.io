const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
async function fingerprint(ip,secret){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const sig=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(ip));return Array.from(new Uint8Array(sig),b=>b.toString(16).padStart(2,"0")).join("");}
const adminCookie=request=>(request.headers.get("cookie")||"").match(/(?:^|;\\s*)livre_admin=([^;]+)/)?.[1]||"";
async function adminSignature(value,secret){return fingerprint(value,secret)}
async function isAdmin(request,env){
 if(!env.LIVRE_OR_ADMIN_PASSWORD)return false;
 const token=adminCookie(request),parts=token.split(".");
 if(parts.length!==2||!/^[0-9]{10,13}$/.test(parts[0])||!Number.isFinite(+parts[0])||Date.now()>+parts[0]||+parts[0]>Date.now()+43200000)return false;
 const expected=await adminSignature(parts[0],env.LIVRE_OR_ADMIN_PASSWORD);
 return expected===parts[1];
}
const cookieId=request=>{const value=(request.headers.get("cookie")||"").match(/(?:^|;\s*)livre_visiteur=([a-f0-9-]{36})(?:;|$)/i)?.[1];return value||null};
export async function onRequestGet({request,env}) {
 if(!env.DB)return json({error:"Base de données non connectée."},503);
 const url=new URL(request.url),page=Math.max(1,Math.min(100000,Number.parseInt(url.searchParams.get("page")||"1",10)||1)),size=3;
 try{
 const count=await env.DB.prepare("SELECT COUNT(*) AS total FROM commentaires").first();
 const total=count?.total||0,pages=Math.max(1,Math.ceil(total/size)),current=Math.min(page,pages);
 const {results}=await env.DB.prepare("SELECT id,pseudo,message,date_creation FROM commentaires ORDER BY id DESC LIMIT ? OFFSET ?").bind(size,(current-1)*size).all();
 const admin=await isAdmin(request,env);
 let remaining=null;
 if(!admin&&env.LIVRE_OR_SECRET && request.headers.get("cf-connecting-ip")){
 const hash=await fingerprint(request.headers.get("cf-connecting-ip"),env.LIVRE_OR_SECRET);
 const id=cookieId(request);
 const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM commentaires WHERE ip_hash=? OR visiteur_id=?").bind(hash,id||"").first();
 remaining=Math.max(0,3-(row?.n||0));
 }
 return json({messages:results,total,page:current,pages,remaining,admin});
 }catch(e){return json({error:"Impossible de charger les messages."},500)}
}
export async function onRequestPost({request,env}) {
 if(!env.DB||!env.LIVRE_OR_SECRET)return json({error:"Configuration du livre d'or incomplète."},503);
 const origin=request.headers.get("origin");if(origin && origin!==new URL(request.url).origin)return json({error:"Origine non autorisée."},403);
 const ip=request.headers.get("cf-connecting-ip");if(!ip)return json({error:"Impossible de vérifier la limite de messages."},403);
 let data;try{data=await request.json()}catch{return json({error:"Données invalides."},400)}
 if(data.website)return json({ok:true});
 const pseudo=String(data.pseudo||"").trim(),message=String(data.message||"").trim();
 if(pseudo.length<2||pseudo.length>32||message.length<2||message.length>500)return json({error:"Pseudo : 2–32 caractères. Message : 2–500 caractères."},400);
 const admin=await isAdmin(request,env);
 const hash=await fingerprint(ip,env.LIVRE_OR_SECRET),id=cookieId(request)||crypto.randomUUID();
 try{
 const stats=await env.DB.prepare("SELECT COUNT(*) AS n, MAX(date_creation) AS last FROM commentaires WHERE ip_hash=? OR visiteur_id=?").bind(hash,id).first();
 if(!admin&&(stats?.n||0)>=3)return json({error:"La limite de 3 messages est atteinte pour cette connexion."},429);
 if(!admin&&stats?.last && Date.now()-Date.parse(stats.last.replace(" ","T")+"Z")<60000)return json({error:"Attends une minute avant de publier un autre message."},429);
 await env.DB.prepare("INSERT INTO commentaires (pseudo,message,visiteur_id,ip_hash) VALUES (?,?,?,?)").bind(pseudo,message,id,hash).run();
 return json({ok:true},201,{"set-cookie":`livre_visiteur=${id}; Path=/; Max-Age=31536000; SameSite=Lax; Secure; HttpOnly`});
 }catch(e){return json({error:"Publication impossible. Réessaie."},500)}
}
