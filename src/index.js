const SESSION_SECONDS = 60 * 60 * 12;
const PBKDF2_ITERATIONS = 100000;
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const randomToken = (n=32) => { const b=new Uint8Array(n); crypto.getRandomValues(b); return b64url(b); };
const digest = async value => b64url(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)));
const passwordHash = async (password,salt,iterations=PBKDF2_ITERATIONS) => {
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
 const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations,hash:"SHA-256"},key,256);
 return b64url(bits);
};
const cookieToken = request => (request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("tendora_admin="))?.slice("tendora_admin=".length)||"";
const cookie = (token,maxAge=SESSION_SECONDS) => `tendora_admin=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
const sameOrigin = request => { const origin=request.headers.get("Origin"); return !origin || origin===new URL(request.url).origin; };
async function currentAdmin(request,env) {
 const token=cookieToken(request); if(!token) return null;
 const tokenHash=await digest(token);
 return await env.DB.prepare("SELECT a.id,a.email,a.display_name,a.role,a.status,a.password_reset_required FROM admin_sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.status='active'").bind(tokenHash,new Date().toISOString()).first();
}
async function audit(env,adminId,action,type=null,id=null,details={}) {
 await env.DB.prepare("INSERT INTO admin_audit_logs(id,admin_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),adminId,action,type,id,JSON.stringify(details)).run();
}

function decodeEntities(value) {
 return String(value||"").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,"$1").replace(/<[^>]*>/g," ").replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&").replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n))).replace(/\s+/g," ").trim();
}
function safePublicUrl(value) {
 try {
  const u=new URL(value);
  if(u.protocol!=="https:" || u.username || u.password || (u.port && u.port!=="443")) return null;
  const h=u.hostname.toLowerCase();
  if(h.startsWith("[") || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) || h==="localhost" || h.endsWith(".localhost") || h.endsWith(".internal") || h.endsWith(".local") || h==="metadata.google.internal") return null;
  return u;
 } catch { return null; }
}
async function boundedText(response,maxBytes=1000000) {
 const declared=Number(response.headers.get("content-length")||0);
 if(declared>maxBytes) throw new Error("Source page is larger than the 1 MB safety limit.");
 if(!response.body) return "";
 const reader=response.body.getReader(), chunks=[]; let size=0;
 try {
  while(true) {
   const {done,value}=await reader.read(); if(done) break;
   size+=value.byteLength; if(size>maxBytes){await reader.cancel();throw new Error("Source page exceeded the 1 MB safety limit.");}
   chunks.push(value);
  }
 } finally { try{reader.releaseLock()}catch{} }
 const all=new Uint8Array(size);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.byteLength;}
 return new TextDecoder("utf-8",{fatal:false}).decode(all);
}
function extractRssEntries(xml,baseUrl) {
 const blocks=[...xml.matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi)].slice(0,30), out=[];
 for(const match of blocks) {
  const block=match[2];
  const titleMatch=block.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const linkMatch=block.match(/<link\b[^>]*>([\s\S]*?)<\/link>/i);
  const atomLink=block.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*\/?\s*>/i);
  const rawLink=(linkMatch?decodeEntities(linkMatch[1]):atomLink?.[1]||"").trim();
  if(!rawLink) continue;
  let url;try{url=safePublicUrl(new URL(rawLink,baseUrl).href)}catch{continue}
  const title=decodeEntities(titleMatch?.[1]||"");
  const desc=decodeEntities((block.match(/<(?:description|summary|content:encoded)\b[^>]*>([\s\S]*?)<\/(?:description|summary|content:encoded)>/i)||[])[1]||"");
  const date=decodeEntities((block.match(/<(?:pubDate|published|updated)\b[^>]*>([\s\S]*?)<\/(?:pubDate|published|updated)>/i)||[])[1]||"");
  if(title.length>=4 && url) out.push({title:title.slice(0,240),url:url.href,description:desc.slice(0,1200),date});
 }
 return out;
}
function isExcludedJobLink(url,title) {
 const p=url.pathname.toLowerCase(), t=String(title||"").toLowerCase();
 return /\/(?:login|log-in|register|signup|sign-up|forgot|reset-password|support|help|account|profile|about|contact|terms|privacy|blog|news|search|category|tag|feed|feeds|page)(?:\/|$)/.test(p)
  || /\b(forgot password|reset password|sign in|log in|support system|all feeds|newsletter|privacy policy|terms of use)\b/.test(t);
}
function extractJsonLdJobs(html,baseUrl) {
 const out=[];
 const scripts=[...html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)].slice(0,20);
 const visit=value=>{
  if(!value||typeof value!=="object") return;
  if(Array.isArray(value)){for(const item of value)visit(item);return;}
  const type=value["@type"];
  if(type==="JobPosting" || (Array.isArray(type)&&type.includes("JobPosting"))) {
   const title=decodeEntities(value.title||"").slice(0,240);
   const org=value.hiringOrganization;
   const employer=decodeEntities(typeof org==="string"?org:org?.name||"").slice(0,180);
   let target=baseUrl;
   try{target=new URL(value.url||value.sameAs||baseUrl,baseUrl).href}catch{}
   const safe=safePublicUrl(target);
   const description=decodeEntities(value.description||"").slice(0,1200);
   const deadline=String(value.validThrough||"").slice(0,40);
   if(title.length>=5 && safe && !isExcludedJobLink(safe,title)) out.push({title,url:safe.href,employer:employer||null,description,deadline});
  }
  for(const [key,val] of Object.entries(value)) if(key==="@graph" || (val&&typeof val==="object")) visit(val);
 };
 for(const match of scripts) {
  try{visit(JSON.parse(match[1].trim()))}catch{}
 }
 return out;
}
function extractPageLinks(html,baseUrl) {
 const base=new URL(baseUrl), out=[], seen=new Set();
 const host=base.hostname.toLowerCase();
 const re=/<a\b([^>]*?)href\s*=\s*(["'])(.*?)\2([^>]*)>([\s\S]*?)<\/a>/gi;
 for(const m of html.matchAll(re)) {
  const raw=m[3].trim();
  let url;try{url=new URL(raw,base)}catch{continue}
  if(url.protocol!=="https:" || url.hostname!==base.hostname || url.href===base.href || seen.has(url.href)) continue;
  let title=decodeEntities(m[5]).replace(/\s+/g," ").trim();
  const path=url.pathname.toLowerCase();
  if(isExcludedJobLink(url,title)) continue;
  const jobPath=/\/(?:jobs?|careers?|vacanc(?:y|ies)|opportunities|recruitment|positions?|open-roles?|openings?)(?:\/|$)/i.test(path);
  const leaf=path.split("/").filter(Boolean).pop()||"";
  if(/^(?:jobs?|careers?|vacanc(?:y|ies)|opportunities|recruitment|positions?|open-roles?|openings?)$/i.test(leaf)) continue;
  const strongTitle=/\b(intern|internship|trainee|graduate|assistant|analyst|accountant|engineer|technician|officer|manager|director|coordinator|specialist|supervisor|consultant|teacher|driver|nurse|doctor|sales|cashier|developer|designer|pilot|captain|operator|foreman|advisor|adviser|head of|chief)\b/i.test(title);
  if(!jobPath && !strongTitle) continue;
  if(!title || /^(apply|apply now|view|view details|read more|learn more|more|details|open|click here)$/i.test(title)) {
   let slug="";try{slug=decodeURIComponent(path.split("/").filter(Boolean).pop()||"")}catch{}
   if(!slug || !/[a-z]/i.test(slug) || /^(jobs?|careers?|vacancies|opportunities|recruitment|positions?|open-roles?|openings?)$/i.test(slug)) continue;
   title=slug.replace(/[-_]+/g," ").replace(/\s+/g," ").trim().split(" ").map(w=>/^[A-Z0-9]{2,}$/.test(w)?w:w.charAt(0).toUpperCase()+w.slice(1).toLowerCase()).join(" ");
  }
  title=title.replace(/\s+/g," ").trim();
  if(title.length<5 || title.length>240 || isExcludedJobLink(url,title)) continue;
  if(!jobPath && !strongTitle) continue;
  seen.add(url.href);
  out.push({title:title.slice(0,240),url:url.href,employer:null,description:"",date:""});
  if(out.length>=40) break;
 }
 return out;
}
async function discoverFromSource(source) {
 const target=safePublicUrl(source.careers_url);
 if(!target) throw new Error("Source URL is not a permitted public HTTPS address.");
 const response=await fetch(target.href,{method:"GET",redirect:"manual",signal:AbortSignal.timeout(12000),headers:{"User-Agent":"TendoraJobDiscovery/1.1 (+https://tendora.gleesh.workers.dev)","Accept":source.monitoring_method==="rss"?"application/rss+xml, application/atom+xml, application/xml, text/xml":"text/html,application/xhtml+xml"}});
 if(response.status>=300 && response.status<400) throw new Error("Redirected source pages are not followed; update the saved URL to the final HTTPS address.");
 if(!response.ok) throw new Error("Source returned HTTP "+response.status+".");
 const type=(response.headers.get("content-type")||"").toLowerCase(), body=await boundedText(response);
 let entries;
 if(source.monitoring_method==="rss" || /xml|rss|atom/.test(type)) entries=extractRssEntries(body,target.href);
 else entries=[...extractJsonLdJobs(body,target.href),...extractPageLinks(body,target.href)];
 const unique=new Map();
 for(const entry of entries) {
  const key=entry.url.split("#")[0].replace(/\/$/,"");
  if(!unique.has(key)) unique.set(key,entry);
 }
 const result=[...unique.values()].slice(0,40);
 if(!result.length && /enable javascript to run this app|javascript is required|please enable javascript/i.test(body))
  throw new Error("This careers page requires JavaScript. Use manual review or connect an approved public feed/API.");
 return result;
}

async function proxyBackgroundModel(request,url) {
 const modelPath=url.pathname.slice("/hf-models/".length);
 if(!/^Orangebot\/ormbg-ONNX\/resolve\/main\/(?:config\.json|preprocessor_config\.json|onnx\/model_(?:uint8|fp16)\.onnx)$/.test(modelPath)) return new Response("Not found.",{status:404});
 if(!["GET","HEAD"].includes(request.method)) return new Response("Method not allowed.",{status:405,headers:{Allow:"GET, HEAD"}});
 const upstreamUrl=new URL("https://huggingface.co/"+modelPath+url.search);
 const headers=new Headers();
 for(const name of ["range","if-range","if-none-match","if-modified-since"]) { const value=request.headers.get(name);if(value)headers.set(name,value); }
 const upstream=await fetch(upstreamUrl.href,{method:request.method,headers,redirect:"follow"});
 const responseHeaders=new Headers(upstream.headers);
 responseHeaders.set("cache-control","public, max-age=86400");
 responseHeaders.delete("set-cookie");
 return new Response(upstream.body,{status:upstream.status,statusText:upstream.statusText,headers:responseHeaders});
}

async function api(request,env) {
 const url=new URL(request.url), path=url.pathname, method=request.method;
 if(path==="/api/jobs" && method==="GET") {
  const today=new Date().toISOString().slice(0,10);
  const rows=await env.DB.prepare("SELECT id,slug,title,employer,category,employment_type,location,salary_text,description,qualifications,experience,source_url,application_url,deadline,date_verified,published_at FROM jobs WHERE status='published' AND (deadline IS NULL OR deadline='' OR deadline>=?) ORDER BY published_at DESC,created_at DESC LIMIT 100").bind(today).all();
  return json({jobs:rows.results||[],count:(rows.results||[]).length,checkedAt:today},200,{"cache-control":"public, max-age=60, s-maxage=60"});
 }
 if(path==="/api/analytics/click" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const body=await request.json().catch(()=>null), jobId=String(body?.jobId||"").trim();
  if(!/^[a-f0-9-]{36}$/i.test(jobId)) return json({error:"Invalid vacancy reference."},400);
  const today=new Intl.DateTimeFormat("en-CA",{timeZone:"Africa/Kigali",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date());
  const job=await env.DB.prepare("SELECT id FROM jobs WHERE id=? AND status='published' AND (deadline IS NULL OR deadline='' OR deadline>=?)").bind(jobId,today).first();
  if(!job) return json({error:"Vacancy is not currently available."},404);
  await env.DB.prepare("INSERT INTO analytics_events(id,event_type,job_id) VALUES(?,'application_click',?)").bind(crypto.randomUUID(),jobId).run();
  return json({ok:true},202);
 }

 if(path==="/api/analytics/track" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const body=await request.json().catch(()=>null),visitorId=String(body?.visitorId||"").trim(),eventType=String(body?.eventType||""),pagePath=String(body?.pagePath||"").split("?")[0].slice(0,140);
  if(!/^[a-f0-9-]{36}$/i.test(visitorId)||!/^\/[a-z0-9/_-]{0,139}$/i.test(pagePath)||pagePath.includes("..")) return json({error:"Invalid analytics event."},400);
  const toolMap={"/cv-builder.html":"cv-builder","/merge-pdf.html":"merge-pdf","/split-pdf.html":"split-pdf","/pdf-to-word.html":"pdf-to-word","/pdf-to-images.html":"pdf-to-images","/compress-pdf.html":"compress-pdf","/rotate-pdf.html":"rotate-pdf","/add-page-numbers.html":"add-page-numbers","/word-to-pdf.html":"word-to-pdf","/excel-to-pdf.html":"word-to-pdf","/text-to-pdf.html":"text-to-pdf","/image-to-pdf.html":"image-to-pdf","/image-converter.html":"image-converter","/image-compressor.html":"image-compressor","/qr-code-generator.html":"qr-code-generator","/png-to-jpg.html":"png-to-jpg","/background-remover.html":"background-remover","/background-remover":"background-remover"};
  const toolKey=toolMap[pagePath]||null;
  if(!["page_view","tool_use","heartbeat"].includes(eventType)||(eventType==="tool_use"&&!toolKey)) return json({error:"Unsupported analytics event."},400);
  const visitorHash=await digest(visitorId),now=new Date().toISOString();
  await env.DB.prepare("INSERT INTO website_analytics_presence(visitor_hash,current_path,last_seen_at) VALUES(?,?,?) ON CONFLICT(visitor_hash) DO UPDATE SET current_path=excluded.current_path,last_seen_at=excluded.last_seen_at").bind(visitorHash,pagePath,now).run();
  if(eventType==="page_view"||eventType==="tool_use"){
   await env.DB.prepare("INSERT INTO website_analytics_events(id,event_type,visitor_hash,page_path,tool_key) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(),eventType,visitorHash,pagePath,toolKey).run();
   if(eventType==="page_view") await env.DB.prepare("DELETE FROM website_analytics_presence WHERE last_seen_at < ?").bind(new Date(Date.now()-86400000).toISOString()).run();
  }
  return json({ok:true},202);
 }
 if(path==="/api/admin/status" && method==="GET") {
  const row=await env.DB.prepare("SELECT COUNT(*) AS count FROM admins").first();
  return json({setupRequired:Number(row.count)===0});
 }
 if(path==="/api/admin/setup" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!env.ADMIN_SETUP_TOKEN) return json({error:"Initial setup is not enabled."},503);
  const count=await env.DB.prepare("SELECT COUNT(*) AS count FROM admins").first();
  if(Number(count.count)>0) return json({error:"Initial setup has already been completed."},409);
  const body=await request.json().catch(()=>null);
  if(!body || typeof body.setupToken!=="string" || body.setupToken!==env.ADMIN_SETUP_TOKEN) return json({error:"Invalid setup code."},403);
  const email=String(body.email||"").trim().toLowerCase(), name=String(body.name||"").trim(), password=String(body.password||"");
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || name.length<2 || password.length<8) return json({error:"Enter a valid email, name and password of at least 8 characters."},400);
  const salt=randomToken(16), hash=await passwordHash(password,salt);
  const id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO admins(id,email,display_name,password_hash,password_salt,password_iterations,role,status) VALUES(?,?,?,?,?,?, 'owner','active')").bind(id,email,name,hash,salt,PBKDF2_ITERATIONS).run();
  await audit(env,id,"owner_account_created","admin",id,{email});
  return createSession(id,request,env);
 }
 if(path==="/api/admin/login" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const ip=request.headers.get("CF-Connecting-IP")||"unknown";
  const ipHash=await digest(ip);
  const attempt=await env.DB.prepare("SELECT attempt_count,window_started_at FROM admin_login_attempts WHERE ip_hash=?").bind(ipHash).first();
  const now=Date.now(), windowStart=attempt?Date.parse(attempt.window_started_at):0;
  if(attempt && now-windowStart<15*60*1000 && Number(attempt.attempt_count)>=8) return json({error:"Too many sign-in attempts. Try again in 15 minutes."},429);
  const body=await request.json().catch(()=>null);
  const email=String(body?.email||"").trim().toLowerCase(), password=String(body?.password||"");
   if(password.length<8) return json({error:"Password must be at least 8 characters."},400);
  const admin=await env.DB.prepare("SELECT * FROM admins WHERE email=? AND status='active'").bind(email).first();
  const candidate=admin?await passwordHash(password,admin.password_salt,admin.password_iterations):"";
  if(!admin || candidate!==admin.password_hash) {
   if(!attempt || now-windowStart>=15*60*1000) await env.DB.prepare("INSERT INTO admin_login_attempts(ip_hash,attempt_count,window_started_at,last_attempt_at) VALUES(?,1,?,?) ON CONFLICT(ip_hash) DO UPDATE SET attempt_count=1,window_started_at=excluded.window_started_at,last_attempt_at=excluded.last_attempt_at").bind(ipHash,new Date().toISOString(),new Date().toISOString()).run();
   else await env.DB.prepare("UPDATE admin_login_attempts SET attempt_count=attempt_count+1,last_attempt_at=? WHERE ip_hash=?").bind(new Date().toISOString(),ipHash).run();
   return json({error:"Email or password is incorrect."},401);
  }
  await env.DB.prepare("DELETE FROM admin_login_attempts WHERE ip_hash=?").bind(ipHash).run();
  return createSession(admin.id,request,env);
 }
 if(path==="/api/admin/logout" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const token=cookieToken(request); if(token) await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash=?").bind(await digest(token)).run();
  return json({ok:true},200, { "set-cookie":cookie("",0) });
 }
 if(path==="/api/tools" && method==="GET") {
  const rows=await env.DB.prepare("SELECT tool_key,display_name,description,category,featured FROM tool_settings WHERE enabled=1 ORDER BY category,display_name").all();
  return json({tools:rows.results||[]},200,{"cache-control":"public, max-age=60, s-maxage=60"});
 }
 const admin=await currentAdmin(request,env);
 if(!admin) return json({error:"Authentication required."},401);
 if(admin.password_reset_required && !(path==="/api/admin/me" && method==="GET") && !(path==="/api/admin/change-password" && method==="POST")) return json({error:"You must change your temporary password before continuing."},403);
 if(path==="/api/admin/me" && method==="GET") return json({admin});
 if(path==="/api/admin/change-password" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const b=await request.json().catch(()=>null), currentPassword=String(b?.currentPassword||""), nextPassword=String(b?.newPassword||"");
  if(nextPassword.length<8 || nextPassword.length>200) return json({error:"Your new password must contain at least 8 characters."},400);
  const record=await env.DB.prepare("SELECT password_hash,password_salt,password_iterations FROM admins WHERE id=? AND status='active'").bind(admin.id).first();
  const currentHash=await passwordHash(currentPassword,record.password_salt,record.password_iterations);
  if(currentHash!==record.password_hash) return json({error:"Current password is incorrect."},400);
  const salt=randomToken(16), hash=await passwordHash(nextPassword,salt);
  await env.DB.prepare("UPDATE admins SET password_hash=?,password_salt=?,password_iterations=?,password_reset_required=0,updated_at=? WHERE id=?").bind(hash,salt,PBKDF2_ITERATIONS,new Date().toISOString(),admin.id).run();
  const token=cookieToken(request), tokenHash=token?await digest(token):"";
  await env.DB.prepare("DELETE FROM admin_sessions WHERE admin_id=? AND token_hash<>?").bind(admin.id,tokenHash).run();
  await audit(env,admin.id,"admin_password_changed","admin",admin.id,{});
  const updated=await env.DB.prepare("SELECT id,email,display_name,role,status,password_reset_required FROM admins WHERE id=?").bind(admin.id).first();
  return json({ok:true,admin:updated});
 }
 if(path==="/api/admin/administrators" && method==="GET") {
  if(admin.role!=="owner") return json({error:"Only the Owner can manage administrator accounts."},403);
  const rows=await env.DB.prepare("SELECT id,email,display_name,role,status,created_at,last_login_at FROM admins ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'editor' THEN 2 ELSE 3 END,display_name").all();
  return json({administrators:rows.results||[]});
 }
 if(path==="/api/admin/administrators" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(admin.role!=="owner") return json({error:"Only the Owner can create administrator accounts."},403);
  const b=await request.json().catch(()=>null), email=String(b?.email||"").trim().toLowerCase(), name=String(b?.displayName||"").trim(), role=String(b?.role||"");
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || name.length<2 || name.length>100 || !["admin","editor","reviewer"].includes(role)) return json({error:"Enter a valid email, name and permitted role."},400);
  const exists=await env.DB.prepare("SELECT id FROM admins WHERE email=?").bind(email).first();
  if(exists) return json({error:"An administrator with this email already exists."},409);
  const temporaryPassword=randomToken(18), salt=randomToken(16), hash=await passwordHash(temporaryPassword,salt), id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO admins(id,email,display_name,password_hash,password_salt,password_iterations,role,status,password_reset_required) VALUES(?,?,?,?,?,?,?,'active',1)").bind(id,email,name,hash,salt,PBKDF2_ITERATIONS,role).run();
  await audit(env,admin.id,"admin_created","admin",id,{email,display_name:name,role});
  return json({ok:true,id,temporaryPassword},201);
 }
 const administratorMatch=path.match(/^\/api\/admin\/administrators\/([a-f0-9-]+)(?:\/(reset-password))?$/i);
 if(administratorMatch) {
  if(admin.role!=="owner") return json({error:"Only the Owner can manage administrator accounts."},403);
  const targetId=administratorMatch[1], action=administratorMatch[2]||null;
  const target=await env.DB.prepare("SELECT id,email,display_name,role,status FROM admins WHERE id=?").bind(targetId).first();
  if(!target) return json({error:"Administrator not found."},404);
  if(target.role==="owner") return json({error:"The Owner account cannot be changed or reset here."},403);
  if(method==="PATCH" && !action) {
   if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
   const b=await request.json().catch(()=>null), name=String(b?.displayName??target.display_name).trim(), role=String(b?.role??target.role), status=String(b?.status??target.status);
   if(name.length<2 || name.length>100 || !["admin","editor","reviewer"].includes(role) || !["active","disabled"].includes(status)) return json({error:"Enter a valid name, role and account status."},400);
   if(targetId===admin.id && status!=="active") return json({error:"You cannot disable your own account."},400);
   await env.DB.prepare("UPDATE admins SET display_name=?,role=?,status=?,updated_at=? WHERE id=?").bind(name,role,status,new Date().toISOString(),targetId).run();
   if(status==="disabled") await env.DB.prepare("DELETE FROM admin_sessions WHERE admin_id=?").bind(targetId).run();
   await audit(env,admin.id,"admin_updated","admin",targetId,{email:target.email,display_name:name,role,status});
   return json({ok:true});
  }
  if(method==="POST" && action==="reset-password") {
   if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
   if(targetId===admin.id) return json({error:"Use your own password-change screen to change the Owner password."},400);
   if(target.status!=="active") return json({error:"Enable this account before resetting its password."},409);
   const temporaryPassword=randomToken(18), salt=randomToken(16), hash=await passwordHash(temporaryPassword,salt);
   await env.DB.prepare("UPDATE admins SET password_hash=?,password_salt=?,password_iterations=?,password_reset_required=1,updated_at=? WHERE id=?").bind(hash,salt,PBKDF2_ITERATIONS,new Date().toISOString(),targetId).run();
   await env.DB.prepare("DELETE FROM admin_sessions WHERE admin_id=?").bind(targetId).run();
   await audit(env,admin.id,"admin_password_reset","admin",targetId,{email:target.email});
   return json({ok:true,temporaryPassword});
  }
 }


 if(path==="/api/admin/profile" && method==="GET") {
  const profile=await env.DB.prepare("SELECT id,email,display_name,role,status,avatar_data_url FROM admins WHERE id=?").bind(admin.id).first();
  return json({profile});
 }
 if(path==="/api/admin/profile" && method==="PATCH") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  const b=await request.json().catch(()=>null), name=String(b?.displayName??admin.display_name).trim();
  if(name.length<2 || name.length>100) return json({error:"Display name must contain 2 to 100 characters."},400);
  let avatar=b?.avatarDataUrl;
  if(avatar!==undefined && avatar!==null && (typeof avatar!=="string" || avatar.length>200000 || !/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/.test(avatar))) return json({error:"Profile photo must be JPEG, PNG or WebP and no larger than 150 KB after resizing."},400);
  if(avatar===undefined) await env.DB.prepare("UPDATE admins SET display_name=?,updated_at=? WHERE id=?").bind(name,new Date().toISOString(),admin.id).run();
  else await env.DB.prepare("UPDATE admins SET display_name=?,avatar_data_url=?,updated_at=? WHERE id=?").bind(name,avatar,new Date().toISOString(),admin.id).run();
  await audit(env,admin.id,"admin_profile_updated","admin",admin.id,{display_name:name,photo_changed:avatar!==undefined});
  const profile=await env.DB.prepare("SELECT id,email,display_name,role,status,avatar_data_url FROM admins WHERE id=?").bind(admin.id).first();
  return json({ok:true,profile});
 }
 if(path==="/api/admin/tools" && method==="GET") {
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an Owner or Admin can manage document tools."},403);
  const rows=await env.DB.prepare("SELECT tool_key,display_name,description,category,enabled,featured,updated_at FROM tool_settings ORDER BY category,display_name").all();
  return json({tools:rows.results||[]});
 }
 const toolMatch=path.match(/^\/api\/admin\/tools\/([a-z0-9-]+)$/);
 if(toolMatch && method==="PATCH") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an Owner or Admin can manage document tools."},403);
  const key=toolMatch[1], existing=await env.DB.prepare("SELECT * FROM tool_settings WHERE tool_key=?").bind(key).first();
  if(!existing) return json({error:"Document tool not found."},404);
  const b=await request.json().catch(()=>null), enabled=b?.enabled===undefined?existing.enabled:(b.enabled?1:0), featured=b?.featured===undefined?existing.featured:(b.featured?1:0);
  await env.DB.prepare("UPDATE tool_settings SET enabled=?,featured=?,updated_by=?,updated_at=? WHERE tool_key=?").bind(enabled,featured,admin.id,new Date().toISOString(),key).run();
  await audit(env,admin.id,"document_tool_updated","document_tool",key,{enabled,featured});
  return json({ok:true});
 }
 if(path==="/api/admin/settings" && method==="GET") {
  const rows=await env.DB.prepare("SELECT setting_key,setting_value,updated_at FROM site_settings ORDER BY setting_key").all();
  return json({settings:Object.fromEntries((rows.results||[]).map(x=>[x.setting_key,x.setting_value]))});
 }
 if(path==="/api/admin/settings" && method==="PATCH") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(admin.role!=="owner") return json({error:"Only the Owner can change general settings."},403);
  const b=await request.json().catch(()=>null), allowed={site_name:["Tendora"],default_language:["English","Kinyarwanda"],timezone:["Africa/Kigali","UTC"],default_job_location:["Rwanda","Kigali","All Rwanda"]};
  for(const [key,value] of Object.entries(b||{})) if(!allowed[key] || !allowed[key].includes(String(value))) return json({error:"One or more settings contain an unsupported value."},400);
  for(const [key,value] of Object.entries(b||{})) await env.DB.prepare("INSERT INTO site_settings(setting_key,setting_value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=excluded.updated_at").bind(key,String(value),admin.id,new Date().toISOString()).run();
  await audit(env,admin.id,"site_settings_updated","settings",null,b||{});
  const rows=await env.DB.prepare("SELECT setting_key,setting_value FROM site_settings").all();
  return json({ok:true,settings:Object.fromEntries((rows.results||[]).map(x=>[x.setting_key,x.setting_value]))});
 }

 if(path==="/api/admin/overview" && method==="GET") {
  const [jobs,admins,sources,candidates,activeSources,recent,latest]=await Promise.all([
   env.DB.prepare("SELECT status,COUNT(*) AS count FROM jobs GROUP BY status").all(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM admins WHERE status='active'").first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM job_sources").first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM discovery_candidates WHERE status IN ('new','reviewing')").first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM job_sources WHERE monitoring_enabled=1 AND monitoring_method IN ('rss','public_page')").first(),
   env.DB.prepare("SELECT l.action,l.entity_type,l.entity_id,l.created_at,a.display_name AS admin_name FROM admin_audit_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.created_at DESC LIMIT 6").all(),
   env.DB.prepare("SELECT id,title,employer,location,published_at FROM jobs WHERE status='published' ORDER BY published_at DESC LIMIT 5").all()
  ]);
  const counts={}; for(const x of jobs.results||[]) counts[x.status]=x.count;
  return json({jobs:counts,admins:admins.count,sources:sources.count,discoveryPending:candidates.count,activeSources:activeSources.count,recentActivity:recent.results||[],latestPublished:latest.results||[]});
 }

 if(path==="/api/admin/analytics" && method==="GET") {
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an Owner or Admin can view analytics."},403);
  const requested=Number.parseInt(url.searchParams.get("days")||"30",10),days=[7,30,90].includes(requested)?requested:30;
  const today=new Intl.DateTimeFormat("en-CA",{timeZone:"Africa/Kigali",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date());
  const [year,month,day]=today.split("-").map(Number),todayUtc=Date.UTC(year,month-1,day),startDay=new Date(todayUtc-(days-1)*86400000).toISOString().slice(0,10),cutoffUtc=new Date(todayUtc-(days-1)*86400000-2*3600000).toISOString(),onlineCutoff=new Date(Date.now()-300000).toISOString();
  const [jobCounts,clickCounts,clickTrend,publishedTrend,topJobs,sources,candidates,trafficCounts,onlineCounts,trafficTrend,toolUsage,topPages]=await Promise.all([
   env.DB.prepare("SELECT SUM(CASE WHEN status='published' AND (deadline IS NULL OR deadline='' OR deadline>=?) THEN 1 ELSE 0 END) AS live_published,SUM(CASE WHEN status='published' AND deadline IS NOT NULL AND deadline<>'' AND deadline<? THEN 1 ELSE 0 END) AS expired,SUM(CASE WHEN status IN ('pending_verification','pending_approval') THEN 1 ELSE 0 END) AS pending_review,SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected,SUM(CASE WHEN status='draft' THEN 1 ELSE 0 END) AS drafts,SUM(CASE WHEN status='published' AND published_at>=? THEN 1 ELSE 0 END) AS published_in_period FROM jobs WHERE status<>'archived'").bind(today,today,cutoffUtc).first(),
   env.DB.prepare("SELECT COUNT(*) AS all_time,SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS period FROM analytics_events WHERE event_type='application_click'").bind(cutoffUtc).first(),
   env.DB.prepare("SELECT date(created_at,'+2 hours') AS day,COUNT(*) AS clicks FROM analytics_events WHERE event_type='application_click' AND date(created_at,'+2 hours')>=? GROUP BY date(created_at,'+2 hours') ORDER BY day").bind(startDay).all(),
   env.DB.prepare("SELECT date(published_at,'+2 hours') AS day,COUNT(*) AS published FROM jobs WHERE status='published' AND published_at IS NOT NULL AND date(published_at,'+2 hours')>=? GROUP BY date(published_at,'+2 hours') ORDER BY day").bind(startDay).all(),
   env.DB.prepare("SELECT j.id,j.title,j.employer,COUNT(e.id) AS clicks FROM jobs j LEFT JOIN analytics_events e ON e.job_id=j.id AND e.event_type='application_click' AND e.created_at>=? WHERE j.status='published' GROUP BY j.id ORDER BY clicks DESC,j.published_at DESC LIMIT 10").bind(cutoffUtc).all(),
   env.DB.prepare("SELECT name,monitoring_method,monitoring_enabled,last_checked_at,last_status FROM job_sources ORDER BY monitoring_enabled DESC,name LIMIT 30").all(),
   env.DB.prepare("SELECT status,COUNT(*) AS count FROM discovery_candidates GROUP BY status").all(),
   env.DB.prepare("SELECT COUNT(*) AS all_time_views,SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS period_views,COUNT(DISTINCT visitor_hash) AS all_time_visitors,COUNT(DISTINCT CASE WHEN created_at>=? THEN visitor_hash END) AS period_visitors FROM website_analytics_events WHERE event_type='page_view'").bind(cutoffUtc,cutoffUtc).first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM website_analytics_presence WHERE last_seen_at>=?").bind(onlineCutoff).first(),
   env.DB.prepare("SELECT date(created_at,'+2 hours') AS day,COUNT(*) AS views,COUNT(DISTINCT visitor_hash) AS visitors FROM website_analytics_events WHERE event_type='page_view' AND date(created_at,'+2 hours')>=? GROUP BY date(created_at,'+2 hours') ORDER BY day").bind(startDay).all(),
   env.DB.prepare("SELECT e.tool_key,COALESCE(t.display_name,e.tool_key) AS tool_name,COUNT(*) AS all_time_uses,SUM(CASE WHEN e.created_at>=? THEN 1 ELSE 0 END) AS period_uses,COUNT(DISTINCT CASE WHEN e.created_at>=? THEN e.visitor_hash END) AS period_users FROM website_analytics_events e LEFT JOIN tool_settings t ON t.tool_key=e.tool_key WHERE e.event_type='tool_use' GROUP BY e.tool_key ORDER BY period_uses DESC,all_time_uses DESC").bind(cutoffUtc,cutoffUtc).all(),
   env.DB.prepare("SELECT page_path,COUNT(*) AS views,COUNT(DISTINCT visitor_hash) AS visitors FROM website_analytics_events WHERE event_type='page_view' AND created_at>=? GROUP BY page_path ORDER BY views DESC LIMIT 12").bind(cutoffUtc).all()
  ]);
  const clickMap=new Map((clickTrend.results||[]).map(x=>[x.day,Number(x.clicks||0)])),publishedMap=new Map((publishedTrend.results||[]).map(x=>[x.day,Number(x.published||0)])),trafficMap=new Map((trafficTrend.results||[]).map(x=>[x.day,{views:Number(x.views||0),visitors:Number(x.visitors||0)}]));
  const dailyClicks=[],dailyPublished=[],dailyTraffic=[];
  for(let i=0;i<days;i++){const date=new Date(todayUtc-(days-1-i)*86400000).toISOString().slice(0,10);dailyClicks.push({day:date,clicks:clickMap.get(date)||0});dailyPublished.push({day:date,published:publishedMap.get(date)||0});const v=trafficMap.get(date)||{};dailyTraffic.push({day:date,views:v.views||0,visitors:v.visitors||0});}
  const discovery={};for(const row of candidates.results||[])discovery[row.status]=Number(row.count||0);
  const c=jobCounts||{},k=clickCounts||{},t=trafficCounts||{};
  return json({days,today,summary:{livePublished:Number(c.live_published||0),expired:Number(c.expired||0),pendingReview:Number(c.pending_review||0),rejected:Number(c.rejected||0),drafts:Number(c.drafts||0),publishedInPeriod:Number(c.published_in_period||0),allTimeClicks:Number(k.all_time||0),periodClicks:Number(k.period||0)},traffic:{allTimeViews:Number(t.all_time_views||0),periodViews:Number(t.period_views||0),allTimeVisitors:Number(t.all_time_visitors||0),periodVisitors:Number(t.period_visitors||0),onlineNow:Number(onlineCounts?.count||0)},dailyClicks,dailyPublished,dailyTraffic,toolUsage:toolUsage.results||[],topPages:topPages.results||[],topJobs:topJobs.results||[],sources:sources.results||[],discovery});
 }
 if(path==="/api/admin/activity" && method==="GET") {
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can view activity logs."},403);
  const page=Math.max(1,Math.min(10000,Number.parseInt(url.searchParams.get("page")||"1",10)||1));
  const limit=50, search=String(url.searchParams.get("search")||"").trim().slice(0,120), action=String(url.searchParams.get("action")||"").trim().slice(0,80);
  const like="%"+search.toLowerCase()+"%";
  const where=" WHERE (?='' OR l.action=?) AND (?='' OR lower(coalesce(a.display_name,'')||' '||coalesce(a.email,'')||' '||l.action||' '||coalesce(l.entity_type,'')||' '||coalesce(l.entity_id,'')||' '||coalesce(l.details_json,'')) LIKE ?)";
  const binds=[action,action,search,like];
  const totalRow=await env.DB.prepare("SELECT COUNT(*) AS total FROM admin_audit_logs l LEFT JOIN admins a ON a.id=l.admin_id"+where).bind(...binds).first();
  const total=Number(totalRow?.total||0), totalPages=Math.max(1,Math.ceil(total/limit)), safePage=Math.min(page,totalPages), offset=(safePage-1)*limit;
  const rows=await env.DB.prepare("SELECT l.id,l.action,l.entity_type,l.entity_id,l.details_json,l.created_at,a.display_name AS admin_name,a.email AS admin_email FROM admin_audit_logs l LEFT JOIN admins a ON a.id=l.admin_id"+where+" ORDER BY l.created_at DESC,l.id DESC LIMIT ? OFFSET ?").bind(...binds,limit,offset).all();
  return json({logs:rows.results||[],total,page:safePage,totalPages,limit});
 }
 if(path==="/api/admin/jobs" && method==="GET") {
  const rows=await env.DB.prepare("SELECT id,title,employer,location,status,deadline,updated_at FROM jobs WHERE status<>'archived' ORDER BY updated_at DESC LIMIT 200").all();
  return json({jobs:rows.results||[]});
 }
 if(path==="/api/admin/recycle-bin" && method==="GET") {
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can access the Recycle Bin."},403);
  const rows=await env.DB.prepare("SELECT id,title,employer,location,updated_at AS deleted_at FROM jobs WHERE status='archived' ORDER BY updated_at DESC LIMIT 500").all();
  return json({jobs:rows.results||[],count:(rows.results||[]).length});
 }
 if(path==="/api/admin/jobs" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin","editor"].includes(admin.role)) return json({error:"You do not have permission to create jobs."},403);
  const b=await request.json().catch(()=>null);
  const title=String(b?.title||"").trim(), employer=String(b?.employer||"").trim(), description=String(b?.description||"").trim(), source=String(b?.sourceUrl||"").trim(), application=String(b?.applicationUrl||"").trim();
  if(!title||!employer||!description||!/^https:\/\//i.test(source)||!/^https:\/\//i.test(application)) return json({error:"Title, employer, description and valid HTTPS source/application URLs are required."},400);
  const id=crypto.randomUUID(), slug=(title+"-"+employer).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,90)+"-"+id.slice(0,8);
  await env.DB.prepare("INSERT INTO jobs(id,slug,title,employer,category,employment_type,location,salary_text,description,qualifications,experience,source_url,application_url,deadline,status,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending_verification',?)").bind(id,slug,title,employer,b.category||null,b.employmentType||null,b.location||null,b.salary||null,description,b.qualifications||null,b.experience||null,source,application,b.deadline||null,admin.id).run();
  await audit(env,admin.id,"job_created","job",id,{title,employer,status:"pending_verification"});
  return json({ok:true,id,status:"pending_verification"},201);
 }
 const jobMatch=path.match(/^\/api\/admin\/jobs\/([a-f0-9-]+)(?:\/(publish|reject|delete|restore|permanent-delete))?$/i);
 if(jobMatch) {
  const jobId=jobMatch[1], action=jobMatch[2]||null;
  const job=await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(jobId).first();
  if(!job) return json({error:"Vacancy not found."},404);
  if(method==="GET" && !action) return json({job});
  if(method==="PATCH" && !action) {
   if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
   if(!["owner","admin","editor"].includes(admin.role)) return json({error:"You do not have permission to edit vacancies."},403);
   const b=await request.json().catch(()=>null);
   const title=String(b?.title||"").trim(), employer=String(b?.employer||"").trim(), description=String(b?.description||"").trim(), source=String(b?.sourceUrl||"").trim(), application=String(b?.applicationUrl||"").trim();
   if(!title||!employer||!description||!/^https:\/\//i.test(source)||!/^https:\/\//i.test(application)) return json({error:"Title, employer, description and valid HTTPS source/application URLs are required."},400);
   await env.DB.prepare("UPDATE jobs SET title=?,employer=?,category=?,employment_type=?,location=?,salary_text=?,description=?,qualifications=?,experience=?,source_url=?,application_url=?,deadline=?,date_verified=NULL,status='pending_verification',verified_by=NULL,approved_by=NULL,published_at=NULL,updated_at=? WHERE id=?").bind(title,employer,b.category||null,b.employmentType||null,b.location||null,b.salary||null,description,b.qualifications||null,b.experience||null,source,application,b.deadline||null,new Date().toISOString(),jobId).run();
   await audit(env,admin.id,"job_updated","job",jobId,{title,previous_status:job.status,new_status:"pending_verification"});
   return json({ok:true,status:"pending_verification"});
  }
  if(method==="POST" && action) {
   if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
   const now=new Date().toISOString();
   if(action==="publish") {
    if(!["owner","admin","reviewer"].includes(admin.role)) return json({error:"You do not have permission to publish vacancies."},403);
    if(!["pending_verification","rejected"].includes(job.status)) return json({error:"Only vacancies awaiting review can be published."},409);
    if(!/^https:\/\//i.test(job.source_url) || !/^https:\/\//i.test(job.application_url)) return json({error:"Valid official source and application links are required before publication."},400);
    if(job.deadline && job.deadline<now.slice(0,10)) return json({error:"This vacancy deadline has passed. Update the deadline before publication."},400);
    const publishedDate=new Intl.DateTimeFormat("en-CA",{timeZone:"Africa/Kigali",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date());
    await env.DB.prepare("UPDATE jobs SET status='published',date_verified=?,verified_by=?,approved_by=?,published_at=?,updated_at=? WHERE id=?").bind(publishedDate,admin.id,admin.id,now,now,jobId).run();
    await audit(env,admin.id,"job_published","job",jobId,{title:job.title});
    return json({ok:true,status:"published"});
   }
   if(action==="delete") {
    if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can delete published vacancies."},403);
    if(job.status!=="published") return json({error:"Only published vacancies can be deleted from this list."},409);
    await env.DB.prepare("UPDATE jobs SET status='archived',updated_at=? WHERE id=?").bind(now,jobId).run();
    await audit(env,admin.id,"job_deleted","job",jobId,{title:job.title,method:"archived"});
    return json({ok:true,status:"archived"});
   }
   if(action==="restore") {
    if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can restore archived vacancies."},403);
    if(job.status!=="archived") return json({error:"Only archived vacancies can be restored."},409);
    await env.DB.prepare("UPDATE jobs SET status='pending_verification',date_verified=NULL,verified_by=NULL,approved_by=NULL,published_at=NULL,updated_at=? WHERE id=?").bind(now,jobId).run();
    await audit(env,admin.id,"job_restored","job",jobId,{title:job.title,new_status:"pending_verification"});
    return json({ok:true,status:"pending_verification"});
   }
   if(action==="permanent-delete") {
    if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can permanently delete vacancies."},403);
    if(job.status!=="archived") return json({error:"Only archived vacancies can be permanently deleted."},409);
    await audit(env,admin.id,"job_permanently_deleted","job",jobId,{title:job.title});
    await env.DB.prepare("DELETE FROM jobs WHERE id=? AND status='archived'").bind(jobId).run();
    return json({ok:true,status:"deleted"});
   }
   if(action==="reject") {
    if(!["owner","admin","reviewer"].includes(admin.role)) return json({error:"You do not have permission to reject vacancies."},403);
    if(job.status!=="pending_verification" && job.status!=="rejected") return json({error:"Only vacancies awaiting review can be rejected."},409);
    const b=await request.json().catch(()=>({}));
    const reason=String(b?.reason||"").trim().slice(0,500);
    if(!reason) return json({error:"Provide a rejection reason."},400);
    await env.DB.prepare("UPDATE jobs SET status='rejected',updated_at=? WHERE id=?").bind(now,jobId).run();
    await audit(env,admin.id,"job_rejected","job",jobId,{title:job.title,reason});
    return json({ok:true,status:"rejected"});
   }
  }
  return json({error:"Method not allowed."},405);
 }
 if(path==="/api/admin/sources" && method==="GET") {
  const rows=await env.DB.prepare("SELECT id,name,organization_type,website_url,careers_url,monitoring_method,monitoring_enabled,last_checked_at,last_status,notes,created_at,updated_at FROM job_sources ORDER BY name").all();
  return json({sources:rows.results||[]});
 }
 if(path==="/api/admin/sources" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can manage recruitment sources."},403);
  const b=await request.json().catch(()=>null);
  const name=String(b?.name||"").trim(), organizationType=String(b?.organizationType||"").trim(), website=String(b?.websiteUrl||"").trim(), careers=String(b?.careersUrl||"").trim(), monitoring=String(b?.monitoringMethod||"manual"), notes=String(b?.notes||"").trim().slice(0,2000);
  const validUrl=value=>{try{const u=new URL(value);return u.protocol==="https:"}catch{return false}};
  if(name.length<2||!validUrl(website)||!validUrl(careers)||!["manual","rss","public_page"].includes(monitoring)) return json({error:"Enter an organization name, valid HTTPS website and careers URLs, and a supported monitoring method."},400);
  const id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO job_sources(id,name,organization_type,website_url,careers_url,monitoring_method,monitoring_enabled,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)").bind(id,name,organizationType||null,website,careers,monitoring,b?.monitoringEnabled===false?0:1,notes||null,admin.id).run();
  await audit(env,admin.id,"job_source_created","job_source",id,{name,monitoring_method:monitoring});
  return json({ok:true,id},201);
 }
 const sourcePrefix="/api/admin/sources/";
 const sourceId=path.startsWith(sourcePrefix)?path.slice(sourcePrefix.length):"";
 if(/^[a-f0-9-]+$/i.test(sourceId) && method==="PATCH") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can manage recruitment sources."},403);
  const id=sourceId, existing=await env.DB.prepare("SELECT * FROM job_sources WHERE id=?").bind(id).first();
  if(!existing) return json({error:"Recruitment source not found."},404);
  const b=await request.json().catch(()=>null);
  const name=String(b?.name??existing.name).trim(), organizationType=String(b?.organizationType??existing.organization_type??"").trim(), website=String(b?.websiteUrl??existing.website_url).trim(), careers=String(b?.careersUrl??existing.careers_url).trim(), monitoring=String(b?.monitoringMethod??existing.monitoring_method), notes=String(b?.notes??existing.notes??"").trim().slice(0,2000);
  const validUrl=value=>{try{const u=new URL(value);return u.protocol==="https:"}catch{return false}};
  if(name.length<2||!validUrl(website)||!validUrl(careers)||!["manual","rss","public_page"].includes(monitoring)) return json({error:"Enter an organization name, valid HTTPS website and careers URLs, and a supported monitoring method."},400);
  const enabled=b?.monitoringEnabled===undefined?existing.monitoring_enabled:(b.monitoringEnabled?1:0);
  await env.DB.prepare("UPDATE job_sources SET name=?,organization_type=?,website_url=?,careers_url=?,monitoring_method=?,monitoring_enabled=?,notes=?,updated_at=? WHERE id=?").bind(name,organizationType||null,website,careers,monitoring,enabled,notes||null,new Date().toISOString(),id).run();
  await audit(env,admin.id,"job_source_updated","job_source",id,{name,monitoring_method:monitoring,monitoring_enabled:enabled});
  return json({ok:true});
 }
 if(path==="/api/admin/discovery" && method==="GET") {
  const rows=await env.DB.prepare("SELECT c.id,c.source_id,c.title,c.employer,c.source_url,c.application_url,c.deadline,c.detected_at,c.status,c.notes,s.name AS source_name FROM discovery_candidates c LEFT JOIN job_sources s ON s.id=c.source_id ORDER BY c.detected_at DESC LIMIT 200").all();
  return json({candidates:rows.results||[]});
 }
 if(path==="/api/admin/discovery/run" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin"].includes(admin.role)) return json({error:"Only an owner or administrator can run source checks."},403);
  const sources=await env.DB.prepare("SELECT * FROM job_sources WHERE monitoring_enabled=1 AND monitoring_method IN ('rss','public_page') ORDER BY last_checked_at IS NOT NULL,last_checked_at LIMIT 8").all();
  const summary={checked:0,discovered:0,duplicates:0,alreadySeen:0,errors:[],sources:[]};
  const results=await Promise.all((sources.results||[]).map(async source=>{
   try {
    const entries=await discoverFromSource(source); let added=0,duplicates=0,alreadySeen=0;
    for(const entry of entries) {
     const normalized=entry.url.split("#")[0].replace(/\/$/,"");
     const prior=await env.DB.prepare("SELECT id FROM discovery_candidates WHERE source_url=? LIMIT 1").bind(normalized).first();
     if(prior){alreadySeen++;continue;}
     const existingJob=entry.employer?await env.DB.prepare("SELECT id FROM jobs WHERE lower(trim(title))=lower(trim(?)) AND lower(trim(employer))=lower(trim(?)) LIMIT 1").bind(entry.title,entry.employer).first():null;
     const id=crypto.randomUUID(), status=existingJob?"duplicate":"new";
     await env.DB.prepare("INSERT INTO discovery_candidates(id,source_id,title,employer,source_url,application_url,deadline,status,notes) VALUES(?,?,?,?,?,?,?,?,?)").bind(id,source.id,entry.title,entry.employer||null,normalized,entry.applicationUrl||normalized,entry.deadline||null,status,entry.description||null).run();
     if(existingJob) duplicates++; else added++;
    }
    const checkedAt=new Date().toISOString();
    const status=entries.length?entries.length+" links: "+added+" new, "+duplicates+" duplicates, "+alreadySeen+" already recorded":"checked: no vacancies found";
    await env.DB.prepare("UPDATE job_sources SET last_checked_at=?,last_status=? WHERE id=?").bind(checkedAt,status,source.id).run();
    return {source:source.name,status,entries:entries.length,discovered:added,duplicates,alreadySeen};
   } catch(error) {
    const message=String(error?.message||error).slice(0,240);
    await env.DB.prepare("UPDATE job_sources SET last_checked_at=?,last_status=? WHERE id=?").bind(new Date().toISOString(),"error: "+message,source.id).run();
    return {source:source.name,status:"error: "+message,error:message,entries:0,discovered:0,duplicates:0,alreadySeen:0};
   }
  }));
  for(const item of results){summary.checked++;summary.discovered+=item.discovered;summary.duplicates+=item.duplicates;summary.alreadySeen+=item.alreadySeen;if(item.error)summary.errors.push({source:item.source,error:item.error});summary.sources.push(item);}
  await audit(env,admin.id,"discovery_sources_checked","discovery",null,summary);
  return json(summary);
 }
 const candidatePrefix="/api/admin/discovery/";
 const candidatePath=path.startsWith(candidatePrefix)?path.slice(candidatePrefix.length):"";
 const candidateMatch=candidatePath.match(/^([a-f0-9-]+)(?:\/(convert|reject|duplicate|review))?$/i);
 if(candidateMatch) {
  const candidateId=candidateMatch[1], action=candidateMatch[2]||null;
  const candidate=await env.DB.prepare("SELECT * FROM discovery_candidates WHERE id=?").bind(candidateId).first();
  if(!candidate) return json({error:"Discovery candidate not found."},404);
  if(method==="POST" && action) {
   if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
   if(!["owner","admin","editor","reviewer"].includes(admin.role)) return json({error:"You do not have permission to review discovery candidates."},403);
   if(action==="review") {
    await env.DB.prepare("UPDATE discovery_candidates SET status='reviewing' WHERE id=? AND status='new'").bind(candidateId).run();
    await audit(env,admin.id,"discovery_candidate_reviewing","discovery_candidate",candidateId,{title:candidate.title});
    return json({ok:true,status:"reviewing"});
   }
   if(action==="reject" || action==="duplicate") {
    const status=action==="duplicate"?"duplicate":"rejected";
    await env.DB.prepare("UPDATE discovery_candidates SET status=? WHERE id=? AND status IN ('new','reviewing')").bind(status,candidateId).run();
    await audit(env,admin.id,"discovery_candidate_"+status,"discovery_candidate",candidateId,{title:candidate.title});
    return json({ok:true,status});
   }
   if(action==="convert") {
    if(!["owner","admin","editor"].includes(admin.role)) return json({error:"You do not have permission to create vacancies."},403);
    if(!["new","reviewing"].includes(candidate.status)) return json({error:"Only active discovery candidates can be converted."},409);
    const id=crypto.randomUUID(),slug=(candidate.title+"-"+candidate.employer).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,90)+"-"+id.slice(0,8);
    const description="Discovered from an official recruitment source. Review the original vacancy and complete all details before publication.";
    await env.DB.prepare("INSERT INTO jobs(id,slug,title,employer,description,source_url,application_url,status,created_by) VALUES(?,?,?,?,?,?,?,'pending_verification',?)").bind(id,slug,candidate.title,candidate.employer||"Unknown employer",description,candidate.source_url,candidate.application_url||candidate.source_url,admin.id).run();
    await env.DB.prepare("UPDATE discovery_candidates SET status='converted',linked_job_id=? WHERE id=?").bind(id,candidateId).run();
    await audit(env,admin.id,"discovery_candidate_converted","discovery_candidate",candidateId,{job_id:id,title:candidate.title});
    return json({ok:true,jobId:id,status:"pending_verification"});
   }
  }
 }
 return json({error:"Not found."},404);
}
async function createSession(adminId,request,env) {
 const token=randomToken(), tokenHash=await digest(token), id=crypto.randomUUID();
 const expires=new Date(Date.now()+SESSION_SECONDS*1000).toISOString();
 await env.DB.prepare("INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at) VALUES(?,?,?,?)").bind(id,adminId,tokenHash,expires).run();
 await env.DB.prepare("UPDATE admins SET last_login_at=?,updated_at=? WHERE id=?").bind(new Date().toISOString(),new Date().toISOString(),adminId).run();
 const admin=await env.DB.prepare("SELECT id,email,display_name,role,status,password_reset_required FROM admins WHERE id=?").bind(adminId).first();
 return json({ok:true,admin},200,{"set-cookie":cookie(token)});
}

const analyticsTracker = `<script>
(()=> {
 const toolPages=new Set(["/cv-builder.html","/merge-pdf.html","/split-pdf.html","/pdf-to-word.html","/pdf-to-images.html","/compress-pdf.html","/rotate-pdf.html","/add-page-numbers.html","/word-to-pdf.html","/excel-to-pdf.html","/text-to-pdf.html","/image-to-pdf.html","/image-converter.html","/image-compressor.html","/qr-code-generator.html","/png-to-jpg.html","/background-remover.html","/background-remover"]);
 const pagePath=location.pathname||"/";let visitorId="";
 try{visitorId=localStorage.getItem("tendora_visitor_id")||""}catch{}
 if(!/^[a-f0-9-]{36}$/i.test(visitorId)){
  try{visitorId=crypto.randomUUID()}catch{const b=crypto.getRandomValues(new Uint8Array(16));visitorId=[...b].map(x=>x.toString(16).padStart(2,"0")).join("").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,"$1-$2-$3-$4-$5")}
  try{localStorage.setItem("tendora_visitor_id",visitorId)}catch{}
 }
 const send=eventType=>fetch("/api/analytics/track",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({visitorId,eventType,pagePath}),keepalive:true}).catch(()=>{});
 send("page_view");
 if(toolPages.has(pagePath))document.addEventListener("click",event=>{
  const button=event.target.closest("button");if(!button||button.disabled)return;
  const id=(button.id||"").toLowerCase(),label=(button.textContent||"").toLowerCase();
  if(/clear|reset|lang|choose|inspect|cancel/.test(id)||/clear|reset|choose|inspect|kinyarwanda/.test(label))return;
  if(/merge|split|convert|compress|rotate|page.?number|create.?pdf|generate|print|resize|make/.test(id+" "+label))send("tool_use");
 },true);
 setInterval(()=>send("heartbeat"),60000);
})();
</script>`;

export default {
 async fetch(request,env) {
  const url=new URL(request.url);
  if(url.pathname.startsWith("/hf-models/")) { try { return await proxyBackgroundModel(request,url); } catch(error) { console.error("Background model proxy failed:",String(error)); return new Response("Model download failed.",{status:502}); } }
  if(url.pathname==="/admin" || url.pathname==="/admin/") return Response.redirect(new URL("/admin.html",url),302);
  if(url.pathname.startsWith("/api/")) {
   try { return await api(request,env); }
   catch(error) { console.error(JSON.stringify({event:"admin_api_error",message:String(error),path:url.pathname})); return json({error:"The request could not be completed."},500); }
  }
  const assetResponse=await env.ASSETS.fetch(request);
  const pagePath=url.pathname==="/" ? "/index.html" : url.pathname;
  if(request.method!=="GET" || pagePath==="/admin.html" || !assetResponse.ok || !(assetResponse.headers.get("content-type")||"").includes("text/html")) return assetResponse;
  const html=await assetResponse.text();
  if(!html.includes("</body>")) return assetResponse;
  const headers=new Headers(assetResponse.headers);
  headers.delete("content-length");headers.delete("content-encoding");headers.delete("etag");headers.delete("last-modified");
  return new Response(html.replace("</body>",analyticsTracker+"</body>"),{status:assetResponse.status,statusText:assetResponse.statusText,headers});
 }
};
