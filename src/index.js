const SESSION_SECONDS = 60 * 60 * 12;
const PBKDF2_ITERATIONS = 310000;
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
async function api(request,env) {
 const url=new URL(request.url), path=url.pathname, method=request.method;
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
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || name.length<2 || password.length<12) return json({error:"Enter a valid email, name and password of at least 12 characters."},400);
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
 if(path==="/api/admin/jobs" && method==="GET") {
  const rows=await env.DB.prepare("SELECT id,title,employer,location,status,deadline,updated_at FROM jobs ORDER BY updated_at DESC LIMIT 200").all();
  return json({jobs:rows.results||[]});
 }
 if(path==="/api/admin/jobs" && method==="POST") {
  if(!sameOrigin(request)) return json({error:"Invalid request origin."},403);
  if(!["owner","admin","editor"].includes(admin.role)) return json({error:"You do not have permission to create jobs."},403);
  const b=await request.json().catch(()=>null);
  const title=String(b?.title||"").trim(), employer=String(b?.employer||"").trim(), description=String(b?.description||"").trim(), source=String(b?.sourceUrl||"").trim(), application=String(b?.applicationUrl||"").trim();
  if(!title||!employer||!description||!/^https:\/\//i.test(source)||!/^https:\/\//i.test(application)) return json({error:"Title, employer, description and valid HTTPS source/application URLs are required."},400);
  const id=crypto.randomUUID(), slug=(title+"-"+employer).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,90)+"-"+id.slice(0,8);
  await env.DB.prepare("INSERT INTO jobs(id,slug,title,employer,category,employment_type,location,salary_text,description,qualifications,experience,source_url,application_url,deadline,date_verified,status,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending_verification',?)").bind(id,slug,title,employer,b.category||null,b.employmentType||null,b.location||null,b.salary||null,description,b.qualifications||null,b.experience||null,source,application,b.deadline||null,b.dateVerified||null,admin.id).run();
  await audit(env,admin.id,"job_created","job",id,{title,employer,status:"pending_verification"});
  return json({ok:true,id,status:"pending_verification"},201);
 }
 if(path==="/api/admin/sources" && method==="GET") {
  const rows=await env.DB.prepare("SELECT id,name,organization_type,website_url,careers_url,monitoring_method,monitoring_enabled,last_checked_at,last_status FROM job_sources ORDER BY name").all();
  return json({sources:rows.results||[]});
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
  if(url.pathname.startsWith("/api/admin/")) {
   try { return await api(request,env); }
   catch(error) { console.error(JSON.stringify({event:"admin_api_error",message:String(error),path:url.pathname})); return json({error:"The request could not be completed."},500); }
  }
  return env.ASSETS.fetch(request);
 }
};
