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
 return await env.DB.prepare("SELECT a.id,a.email,a.display_name,a.role,a.status FROM admin_sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.status='active'").bind(tokenHash,new Date().toISOString()).first();
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
function extractPageLinks(html,baseUrl) {
 const base=new URL(baseUrl), out=[], seen=new Set();
 const re=/<a\b([^>]*?)href\s*=\s*(["'])(.*?)\2([^>]*)>([\s\S]*?)<\/a>/gi;
 for(const m of html.matchAll(re)) {
  let title=decodeEntities(m[5]).replace(/<[^>]*>/g," ").replace(/&nbsp;/gi," ").replace(/\\s+/g," ").trim(), raw=m[3].trim();
  let url;try{url=new URL(raw,base)}catch{continue}
  if(url.protocol!=="https:" || url.hostname!==base.hostname || url.href===base.href || seen.has(url.href)) continue;
  const generic=/^(explore more|read more|view more|view details|learn more|apply now|more details)$/i.test(title);
  if(generic || title.length<5 || title.length>240) {
   let slug="";try{slug=decodeURIComponent(url.pathname.split("/").filter(Boolean).pop()||"")}catch{}
   if(!slug) continue;
   title=slug.replace(/[-_]+/g," ").replace(/\\s+/g," ").trim().split(" ").map(w=>/^[A-Z0-9]{2,}$/.test(w)?w:w.charAt(0).toUpperCase()+w.slice(1).toLowerCase()).join(" ").replace(/[.]+$/,"");
  }
  if(title.length<5 || title.length>240 || !/(job|career|vacanc|position|recruit|employment|apply|opportunit|internship|consultant|technician|officer|manager|captain|pilot|agent|head|support)/i.test(title+" "+raw)) continue;
  if(seen.has(url.href)) continue;
  seen.add(url.href);out.push({title,url:url.href,description:""});
  if(out.length>=30) break;
 }
 return out;
}
async function discoverFromSource(source) {
 const target=safePublicUrl(source.careers_url); if(!target) throw new Error("Source URL is not a permitted public HTTPS address.");
 const response=await fetch(target.href,{method:"GET",redirect:"manual",signal:AbortSignal.timeout(12000),headers:{"User-Agent":"TendoraJobDiscovery/1.0 (+https://tendora.gleesh.workers.dev)","Accept":source.monitoring_method==="rss"?"application/rss+xml, application/atom+xml, application/xml, text/xml":"text/html,application/xhtml+xml"}});
 if(response.status>=300 && response.status<400) throw new Error("Redirected source pages are not followed; update the saved URL to the final HTTPS address.");
 if(!response.ok) throw new Error("Source returned HTTP "+response.status+".");
 const type=(response.headers.get("content-type")||"").toLowerCase(), body=await boundedText(response);
 let entries=source.monitoring_method==="rss" || /xml|rss|atom/.test(type)?extractRssEntries(body,target.href):extractPageLinks(body,target.href);
 return entries.slice(0,30);
}

async function api(request,env) {
 const url=new URL(request.url), path=url.pathname, method=request.method;
 if(path==="/api/jobs" && method==="GET") {
  const today=new Date().toISOString().slice(0,10);
  const rows=await env.DB.prepare("SELECT id,slug,title,employer,category,employment_type,location,salary_text,description,qualifications,experience,source_url,application_url,deadline,date_verified,published_at FROM jobs WHERE status='published' AND (deadline IS NULL OR deadline='' OR deadline>=?) ORDER BY published_at DESC,created_at DESC LIMIT 100").bind(today).all();
  return json({jobs:rows.results||[],count:(rows.results||[]).length,checkedAt:today},200,{"cache-control":"public, max-age=60, s-maxage=60"});
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
 const admin=await currentAdmin(request,env);
 if(!admin) return json({error:"Authentication required."},401);
 if(path==="/api/admin/me" && method==="GET") return json({admin});
 if(path==="/api/admin/overview" && method==="GET") {
  const [jobs,admins,sources,candidates]=await Promise.all([
   env.DB.prepare("SELECT status,COUNT(*) AS count FROM jobs GROUP BY status").all(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM admins WHERE status='active'").first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM job_sources").first(),
   env.DB.prepare("SELECT COUNT(*) AS count FROM discovery_candidates WHERE status IN ('new','reviewing')").first()
  ]);
  const counts={}; for(const x of jobs.results||[]) counts[x.status]=x.count;
  return json({jobs:counts,admins:admins.count,sources:sources.count,discoveryPending:candidates.count});
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
  const sources=await env.DB.prepare("SELECT * FROM job_sources WHERE monitoring_enabled=1 AND monitoring_method IN ('rss','public_page') ORDER BY last_checked_at IS NOT NULL,last_checked_at LIMIT 2").all();
  const summary={checked:0,discovered:0,duplicates:0,errors:[]};
  for(const source of sources.results||[]) {
   try {
    const entries=await discoverFromSource(source); let added=0,duplicates=0;
    for(const entry of entries) {
     const normalized=entry.url.split("#")[0].replace(/\/$/,"");
     const prior=await env.DB.prepare("SELECT id FROM discovery_candidates WHERE source_url=? LIMIT 1").bind(normalized).first();
     const existingJob=await env.DB.prepare("SELECT id FROM jobs WHERE lower(trim(title))=lower(trim(?)) AND lower(trim(employer))=lower(trim(?)) LIMIT 1").bind(entry.title,source.name).first();
     if(prior) continue;
     const id=crypto.randomUUID(), status=existingJob?"duplicate":"new";
     await env.DB.prepare("INSERT INTO discovery_candidates(id,source_id,title,employer,source_url,application_url,status,notes) VALUES(?,?,?,?,?,?,?,?)").bind(id,source.id,entry.title,source.name,normalized,normalized,status,entry.description||null).run();
     if(existingJob) duplicates++; else added++;
    }
    await env.DB.prepare("UPDATE job_sources SET last_checked_at=?,last_status=? WHERE id=?").bind(new Date().toISOString(),"success: "+entries.length+" entries",source.id).run();
    summary.checked++;summary.discovered+=added;summary.duplicates+=duplicates;
   } catch(error) {
    const message=String(error?.message||error).slice(0,240);
    await env.DB.prepare("UPDATE job_sources SET last_checked_at=?,last_status=? WHERE id=?").bind(new Date().toISOString(),"error: "+message,source.id).run();
    summary.errors.push({source:source.name,error:message});
   }
  }
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
 const admin=await env.DB.prepare("SELECT id,email,display_name,role FROM admins WHERE id=?").bind(adminId).first();
 return json({ok:true,admin},200,{"set-cookie":cookie(token)});
}
export default {
 async fetch(request,env) {
  const url=new URL(request.url);
  if(url.pathname==="/admin" || url.pathname==="/admin/") return Response.redirect(new URL("/admin.html",url),302);
  if(url.pathname.startsWith("/api/")) {
   try { return await api(request,env); }
   catch(error) { console.error(JSON.stringify({event:"admin_api_error",message:String(error),path:url.pathname})); return json({error:"The request could not be completed."},500); }
  }
  return env.ASSETS.fetch(request);
 }
};
