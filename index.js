require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname + '/..')); // serve project root statically

function discordCdnAvatarUrl(id, avatar, discriminator) {
  if (avatar) return `https://cdn.discordapp.com/avatars/${id}/${avatar}.png?size=128`;
  const disc = Number(discriminator || 0) % 5;
  return `https://cdn.discordapp.com/embed/avatars/${disc}.png`;
}

// POST /api/auth/exchange-code
// body: { code, redirect_uri }
// Exchanges OAuth2 authorization code for an access token via Discord API
app.post('/api/auth/exchange-code', async (req, res) => {
  try{
    const { code, redirect_uri } = req.body || {};
    if(!code || !redirect_uri){
      return res.status(400).json({ error: 'Missing code or redirect_uri' });
    }
    const client_id = process.env.DISCORD_CLIENT_ID;
    const client_secret = process.env.DISCORD_CLIENT_SECRET;
    if(!client_id || !client_secret){
      return res.status(500).json({ error: 'Missing DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET in env' });
    }
    console.log('[auth] exchange-code called', { has_code: !!code, redirect_uri });
    const form = new URLSearchParams();
    form.set('client_id', client_id);
    form.set('client_secret', client_secret);
    form.set('grant_type', 'authorization_code');
    form.set('code', String(code));
    form.set('redirect_uri', String(redirect_uri));
    const { data } = await axios.post('https://discord.com/api/oauth2/token', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    console.log('[auth] exchange-code OK, expires_in:', data?.expires_in);
    return res.json({ access_token: data.access_token, expires_in: data.expires_in });
  }catch(e){
    const status = e.response?.status || 500;
    const detail = e.response?.data || e.message;
    console.error('[auth] exchange-code ERROR', status, detail);
    return res.status(status).json({ error: 'Code exchange failed', detail });
  }
});

// Quick debug: verify env presence (does NOT expose secrets)
app.get('/api/auth/debug', (req, res) => {
  res.json({
    has_client_id: !!process.env.DISCORD_CLIENT_ID,
    has_client_secret: !!process.env.DISCORD_CLIENT_SECRET,
    port: PORT
  });
});

// GET /api/discord/role-members?guildId=...&roleId=...
app.get('/api/discord/role-members', async (req, res) => {
  const { guildId, roleId } = req.query;
  if (!guildId || !roleId) return res.status(400).json({ error: 'Missing guildId or roleId' });
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) return res.status(500).json({ error: 'Missing DISCORD_BOT_TOKEN' });

  try {
    // Fetch members (requires GUILD_MEMBERS intent enabled on bot)
    // Use pagination with limit=1000 and after parameter if needed; here single page for simplicity
    const url = `https://discord.com/api/v10/guilds/${guildId}/members?limit=1000`;
    const { data } = await axios.get(url, {
      headers: { Authorization: `Bot ${token}` }
    });

    const filtered = (Array.isArray(data) ? data : []).filter(m => Array.isArray(m.roles) && m.roles.includes(roleId));

    const payload = filtered.map(m => ({
      id: m.user?.id || m.id,
      username: m.user?.username,
      global_name: m.user?.global_name,
      display_name: m.nick || m.user?.global_name || m.user?.username,
      discriminator: m.user?.discriminator,
      avatar: m.user?.avatar,
      roles: m.roles,
      avatar_url: discordCdnAvatarUrl(m.user?.id || m.id, m.user?.avatar, m.user?.discriminator)
    }));

    res.json(payload);
  } catch (e) {
    const status = e.response?.status || 500;
    res.status(status).json({ error: 'Discord API error', detail: e.response?.data || e.message });
  }
});

// GET /api/auth/staff-check
// Uses the user's Discord OAuth access token (Authorization: Bearer <token>) to check guild membership and roles.
// Returns { userId, roles, isAdmin, isStaff }
app.get('/api/auth/staff-check', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [scheme, userToken] = auth.split(' ');
    if (!scheme || scheme.toLowerCase() !== 'bearer' || !userToken) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }

    const GUILD_ID = process.env.GUILD_ID;
    const WEBPRAVA_ROLE_ID = process.env.WEBPRAVA_ROLE_ID;
    const ROLE_ADMINS_ID = process.env.ROLE_ADMINS_ID;
    const ROLE_LEADERS_ID = process.env.ROLE_LEADERS_ID;
    const ROLE_TECHNICIANS_ID = process.env.ROLE_TECHNICIANS_ID;
    const ROLE_HL_TECHNICIANS_ID = process.env.ROLE_HL_TECHNICIANS_ID;
    const ROLE_BUILDERS_ID = process.env.ROLE_BUILDERS_ID;
    const ROLE_HL_BUILDERS_ID = process.env.ROLE_HL_BUILDERS_ID;
    const ROLE_HELPERS_ID = process.env.ROLE_HELPERS_ID;
    const ROLE_HL_HELPERS_ID = process.env.ROLE_HL_HELPERS_ID;
    const ROLE_ZK_HELPERS_ID = process.env.ROLE_ZK_HELPERS_ID;

    if (!GUILD_ID) return res.status(500).json({ error: 'Missing GUILD_ID in env' });

    // Identify user
    const meResp = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    const userId = meResp.data?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    // Fetch member for guild to read roles (requires scope guilds.members.read)
    const memberResp = await axios.get(`https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`, {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    const roles = Array.isArray(memberResp.data?.roles) ? memberResp.data.roles : [];

    const staffRoleIds = [
      ROLE_LEADERS_ID,
      ROLE_ADMINS_ID,
      ROLE_TECHNICIANS_ID,
      ROLE_HL_TECHNICIANS_ID,
      ROLE_BUILDERS_ID,
      ROLE_HL_BUILDERS_ID,
      ROLE_HELPERS_ID,
      ROLE_HL_HELPERS_ID,
      ROLE_ZK_HELPERS_ID
    ]
      .filter(Boolean);
    const isStaff = staffRoleIds.some(r => roles.includes(r));
    const isAdmin = Boolean((WEBPRAVA_ROLE_ID && roles.includes(WEBPRAVA_ROLE_ID)) || (ROLE_ADMINS_ID && roles.includes(ROLE_ADMINS_ID)) || isStaff);

    return res.json({ userId, roles, isStaff, isAdmin });
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json({ error: 'Discord check failed', detail: e.response?.data || e.message });
  }
});

// Manual A-Team store
const ATEAM_PATH = path.join(__dirname, 'ateam.json');
function readAteam(){
  try{
    const raw = fs.readFileSync(ATEAM_PATH, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  }catch{
    return [];
  }
}
function writeAteam(list){
  try{
    fs.writeFileSync(ATEAM_PATH, JSON.stringify(list, null, 2), 'utf8');
    return true;
  }catch{
    return false;
  }
}

// GET all manual entries (public)
app.get('/api/ateam/manual', (req, res) => {
  const list = readAteam();
  res.json(list);
});

// POST a manual entry (requires staff auth via server-side check upstream; minimal guard here)
// body: { mcNick: string, position: string }
app.post('/api/ateam/manual', async (req, res) => {
  try{
    const { mcNick, position } = req.body || {};
    if(!mcNick || !position) return res.status(400).json({ error: 'Missing mcNick or position' });

    // Auth: user bearer token required
    const auth = req.headers.authorization || '';
    const [scheme, userToken] = auth.split(' ');
    if (!scheme || scheme.toLowerCase() !== 'bearer' || !userToken) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }

    const GUILD_ID = process.env.GUILD_ID;
    if (!GUILD_ID) return res.status(500).json({ error: 'Missing GUILD_ID in env' });

    // Fetch member roles
    const memberResp = await axios.get(`https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`, {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    const roles = Array.isArray(memberResp.data?.roles) ? memberResp.data.roles : [];

    // Role IDs from env
    const RID_ADMIN = process.env.ROLE_ADMINS_ID; // 1424814414841778218
    const RID_LEADER = process.env.ROLE_LEADERS_ID; // 1424813766088069192
    const RID_HL_TECH = process.env.ROLE_HL_TECHNICIANS_ID; // 1426619538857791518
    const RID_HL_BUILD = process.env.ROLE_HL_BUILDERS_ID; // 1426619736212373504
    const RID_HL_HELP = process.env.ROLE_HL_HELPERS_ID; // 1424815332316418058

    // Compute allowed positions for this user
    const can = new Set();
    if (RID_LEADER && roles.includes(RID_LEADER)) {
      ['Admin','Vedení','HL Technik','Technik','HL Builder','Builder','HL Helper','Helper','ZK Helper'].forEach(p=>can.add(p));
    }
    if (RID_ADMIN && roles.includes(RID_ADMIN)) {
      // Admin role cannot add Admin position
      ['Vedení','HL Technik','Technik','HL Builder','Builder','HL Helper','Helper','ZK Helper'].forEach(p=>can.add(p));
    }
    if (RID_HL_TECH && roles.includes(RID_HL_TECH)) {
      ['Technik'].forEach(p=>can.add(p));
    }
    if (RID_HL_BUILD && roles.includes(RID_HL_BUILD)) {
      ['Builder'].forEach(p=>can.add(p));
    }
    if (RID_HL_HELP && roles.includes(RID_HL_HELP)) {
      ['Helper','ZK Helper'].forEach(p=>can.add(p));
    }

    if (!can.has(String(position))) {
      return res.status(403).json({ error: 'Forbidden for this position' });
    }

    const list = readAteam();
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);
    const item = { id, mcNick: String(mcNick), position: String(position) };
    list.push(item);
    if(!writeAteam(list)) return res.status(500).json({ error: 'Save failed' });
    res.json(item);
  }catch(e){
    const status = e.response?.status || 500;
    res.status(status).json({ error: 'Add failed', detail: e.response?.data || e.message });
  }
});

// DELETE an entry by id
app.delete('/api/ateam/manual/:id', (req, res) => {
  const { id } = req.params;
  if(!id) return res.status(400).json({ error: 'Missing id' });
  const list = readAteam();
  const next = list.filter(x => x.id !== id);
  if(next.length === list.length) return res.status(404).json({ error: 'Not found' });
  if(!writeAteam(next)) return res.status(500).json({ error: 'Save failed' });
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Root route to open the HTML easily
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'novasector.html'));
});

// ===== Tickets storage (JSON on disk) =====
const TICKETS_PATH = path.join(__dirname, 'tickets.json');
function readTickets(){
  try{ const raw = fs.readFileSync(TICKETS_PATH, 'utf8'); const data = JSON.parse(raw); return Array.isArray(data)? data : []; }catch{ return []; }
}
function writeTickets(list){
  try{ fs.writeFileSync(TICKETS_PATH, JSON.stringify(list,null,2), 'utf8'); return true; }catch{ return false; }
}

async function getAuthContext(req){
  const auth = req.headers.authorization || '';
  const [scheme, userToken] = auth.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'bearer' || !userToken) {
    return { ok:false, status:401, error:'Missing bearer token' };
  }
  const GUILD_ID = process.env.GUILD_ID;
  try{
    const meResp = await axios.get('https://discord.com/api/users/@me', { headers:{ Authorization:`Bearer ${userToken}` } });
    const userId = meResp.data?.id;
    const username = meResp.data?.global_name || meResp.data?.username || 'User';
    if(!userId) return { ok:false, status:401, error:'Unauthorized' };
    let roles = [];
    if(GUILD_ID){
      try{
        const memberResp = await axios.get(`https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`, { headers:{ Authorization:`Bearer ${userToken}` } });
        roles = Array.isArray(memberResp.data?.roles) ? memberResp.data.roles : [];
      }catch{
        // Missing scope or not a guild member — proceed with empty roles
        roles = [];
      }
    }
    const staffRoleIds = [process.env.ROLE_LEADERS_ID, process.env.ROLE_ADMINS_ID, process.env.ROLE_TECHNICIANS_ID, process.env.ROLE_HL_TECHNICIANS_ID, process.env.ROLE_BUILDERS_ID, process.env.ROLE_HL_BUILDERS_ID, process.env.ROLE_HELPERS_ID, process.env.ROLE_HL_HELPERS_ID, process.env.ROLE_ZK_HELPERS_ID].filter(Boolean);
    const isStaff = staffRoleIds.some(r => roles.includes(r));
    return { ok:true, userId, roles, username, isStaff };
  }catch(e){
    const status = e.response?.status || 500;
    return { ok:false, status, error: e.response?.data || e.message };
  }
}

function canSeeTicket(ticket, userId, roles){
  const RID_LEADER = process.env.ROLE_LEADERS_ID;             // 1424813766088069192
  const RID_ADMIN = process.env.ROLE_ADMINS_ID;               // 1424814414841778218
  const RID_TECH = process.env.ROLE_TECHNICIANS_ID;           // 1424815027751223296
  const RID_HL_HELP = process.env.ROLE_HL_HELPERS_ID;         // 1424815332316418058
  const RID_HELP = process.env.ROLE_HELPERS_ID;               // 1424815716061675672
  const RID_ZK_HELP = process.env.ROLE_ZK_HELPERS_ID;         // 1424815533878153226
  const isCreator = ticket.creatorId === userId;
  const isSupport = [RID_LEADER, RID_ADMIN, RID_TECH, RID_HL_HELP, RID_HELP, RID_ZK_HELP].filter(Boolean).some(r => roles.includes(r));
  // All tickets now use default category 'Tickets'; visibility by creator or support
  return isCreator || isSupport;
}

function canCloseTicket(ticket, userId, roles){
  const RID_LEADER = process.env.ROLE_LEADERS_ID;
  const RID_ADMIN = process.env.ROLE_ADMINS_ID;
  return roles.includes(RID_ADMIN) || roles.includes(RID_LEADER) || ticket.creatorId === userId;
}

// GET /api/tickets?status=open|closed&category=...
app.get('/api/tickets', async (req,res)=>{
  const ctx = await getAuthContext(req);
  if(!ctx.ok) return res.status(ctx.status).json({ error: ctx.error });
  const { userId, roles } = ctx;
  const status = req.query.status;
  const category = req.query.category;
  const all = readTickets();
  const out = all.filter(t => (!status || (t.status || 'open') === status) && (!category || t.category === category) && canSeeTicket(t, userId, roles));
  res.json(out);
});

// POST /api/tickets  body: { nickname, problem, category, language, attachmentName }
app.post('/api/tickets', async (req,res)=>{
  const ctx = await getAuthContext(req);
  if(!ctx.ok) return res.status(ctx.status).json({ error: ctx.error });
  const { userId, username } = ctx;
  const { nickname, problem, category, description, attachmentName } = req.body || {};
  if(!nickname || !problem) return res.status(400).json({ error:'Missing nickname or problem' });
  const all = readTickets();
  const id = (all.reduce((m,t)=> Math.max(m, Number(t.id)||0), 0) + 1) || 1;
  const item = { id, creatorId:userId, creatorName: username, nickname:String(nickname), problem:String(problem), category: category? String(category): 'Tickets', language:'', description: description? String(description): String(problem), attachmentName: attachmentName? String(attachmentName): '', status:'open', createdAt: Date.now(), messages: [] };
  all.push(item);
  if(!writeTickets(all)) return res.status(500).json({ error:'Save failed' });
  res.json(item);
});

// GET /api/tickets/:id
app.get('/api/tickets/:id', async (req,res)=>{
  const ctx = await getAuthContext(req);
  if(!ctx.ok) return res.status(ctx.status).json({ error: ctx.error });
  const { userId, roles } = ctx;
  const id = Number(req.params.id);
  const all = readTickets();
  const t = all.find(x => Number(x.id) === id);
  if(!t) return res.status(404).json({ error:'Not found' });
  if(!canSeeTicket(t, userId, roles)) return res.status(403).json({ error:'Forbidden' });
  res.json(t);
});

// POST /api/tickets/:id/messages { text }
app.post('/api/tickets/:id/messages', async (req,res)=>{
  const ctx = await getAuthContext(req);
  if(!ctx.ok) return res.status(ctx.status).json({ error: ctx.error });
  const { userId, roles, username, isStaff } = ctx;
  const id = Number(req.params.id);
  const { text } = req.body || {};
  if(!text) return res.status(400).json({ error:'Missing text' });
  const all = readTickets();
  const idx = all.findIndex(x => Number(x.id) === id);
  if(idx === -1) return res.status(404).json({ error:'Not found' });
  const t = all[idx];
  if(!canSeeTicket(t, userId, roles)) return res.status(403).json({ error:'Forbidden' });
  if((t.status || 'open') !== 'open') return res.status(400).json({ error:'Ticket closed' });
  if(!Array.isArray(t.messages)) t.messages = [];
  t.messages.push({ authorId:userId, author:username || 'User', staff: !!isStaff, text:String(text), at: Date.now() });
  if(!writeTickets(all)) return res.status(500).json({ error:'Save failed' });
  res.json({ ok:true });
});

// POST /api/tickets/:id/close
app.post('/api/tickets/:id/close', async (req,res)=>{
  const ctx = await getAuthContext(req);
  if(!ctx.ok) return res.status(ctx.status).json({ error: ctx.error });
  const { userId, roles } = ctx;
  const id = Number(req.params.id);
  const all = readTickets();
  const idx = all.findIndex(x => Number(x.id) === id);
  if(idx === -1) return res.status(404).json({ error:'Not found' });
  const t = all[idx];
  if(!canCloseTicket(t, userId, roles)) return res.status(403).json({ error:'Forbidden' });
  t.status = 'closed';
  if(!writeTickets(all)) return res.status(500).json({ error:'Save failed' });
  res.json({ ok:true });
});

