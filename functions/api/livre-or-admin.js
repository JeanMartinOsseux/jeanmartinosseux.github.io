const reply=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
async function sign(value,secret){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const signature=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value));return Array.from(new Uint8Array(signature),x=>x.toString(16).padStart(2,"0")).join("")}
export async function onRequestPost({request,env}){
 if(!env.LIVRE_OR_ADMIN_PASSWORD)return reply({error:"Définis LIVRE_OR_ADMIN_PASSWORD dans les secrets Cloudflare."},503);
 const origin=request.headers.get("origin");if(origin&&origin!==new URL(request.url).origin)return reply({error:"Origine non autorisée."},403);
 let body;try{body=await request.json()}catch{return reply({error:"Requête invalide."},400)}
 const supplied=String(body.password||"");if(supplied.length>256)return reply({error:"Mot de passe invalide."},401);
 // Compare hashes instead of comparing password strings directly.
 const [a,b]=await Promise.all([sign("admin-login",supplied),sign("admin-login",env.LIVRE_OR_ADMIN_PASSWORD)]);
 if(a!==b)return reply({error:"Mot de passe incorrect."},401);
 const expires=String(Date.now()+12*60*60*1000),signature=await sign(expires,env.LIVRE_OR_ADMIN_PASSWORD);
 return reply({ok:true},200,{"set-cookie":`livre_admin=${expires}.${signature}; Path=/; Max-Age=43200; SameSite=Strict; Secure; HttpOnly`});
}
export async function onRequestDelete({request}){
 const origin=request.headers.get("origin");if(origin&&origin!==new URL(request.url).origin)return reply({error:"Origine non autorisée."},403);
 return reply({ok:true},200,{"set-cookie":"livre_admin=; Path=/; Max-Age=0; SameSite=Strict; Secure; HttpOnly"});
}
