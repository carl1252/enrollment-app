import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL || 'postgres://x');
const SECRET = process.env.JWT_SECRET || '';
const TZ = process.env.TZ_NAME || 'Asia/Manila';
const ST = ['P', 'A', 'L', 'E'];

let ready;
const init = () => (ready ??= (async () => {
  await sql`create table if not exists members(id serial primary key, sn text unique not null, name text not null, pw text not null, contact text, course text, year int, section text, status text not null default 'pending', created_at timestamptz default now())`;
  await sql`create table if not exists attendance(member_id int references members(id) on delete cascade, day date not null, status char(1) not null, primary key(member_id, day))`;
  await sql`create table if not exists checkin(day date primary key, code text not null, open boolean not null default true)`;
})());

const b64 = (x) => Buffer.from(x).toString('base64url');
const mac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const sign = (p) => { const h = b64('{"alg":"HS256"}'), d = b64(JSON.stringify({ ...p, exp: Date.now() + 864e5 })); return `${h}.${d}.${mac(h + '.' + d)}`; };
const verify = (t) => {
  try {
    const [h, d, s] = t.split('.'), ok = mac(h + '.' + d);
    if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return null;
    const p = JSON.parse(Buffer.from(d, 'base64url')); return p.exp > Date.now() ? p : null;
  } catch { return null; }
};
const hashPw = (pw) => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const checkPw = (pw, st) => { const [s, h] = st.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(pw, s, 32), Buffer.from(h, 'hex')); };
const same = (a, b) => { const x = crypto.createHash('sha256').update(String(a)).digest(), y = crypto.createHash('sha256').update(String(b)).digest(); return crypto.timingSafeEqual(x, y); };
const str = (v, n = 80) => String(v ?? '').trim().slice(0, n);
const today = async () => (await sql`select to_char(now() at time zone ${TZ}, 'YYYY-MM-DD') as d`)[0].d;
const isDay = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || '');

export default async function handler(req, res) {
  const send = (c, d) => res.status(c).json(d);
  try {
    if (!SECRET || !process.env.DATABASE_URL) return send(500, { error: 'Server is missing DATABASE_URL or JWT_SECRET' });
    await init();
    const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/api/, '').replace(/\/$/, '') || '/';
    const m = req.method, b = req.body || {}, route = m + ' ' + p;

    if (route === 'POST /register') {
      const sn = str(b.sn, 30), name = str(b.name, 80), pw = String(b.password || ''), year = parseInt(b.year, 10);
      if (!sn || !name || !str(b.course) || !str(b.section) || !(year >= 1 && year <= 5)) return send(400, { error: 'Fill in all required fields' });
      if (pw.length < 6) return send(400, { error: 'Password must be at least 6 characters' });
      if ((await sql`select 1 from members where sn=${sn}`).length) return send(409, { error: 'Student number already registered' });
      await sql`insert into members(sn,name,pw,contact,course,year,section) values(${sn},${name},${hashPw(pw)},${str(b.contact, 40)},${str(b.course, 20).toUpperCase()},${year},${str(b.section, 10).toUpperCase()})`;
      return send(201, { ok: true });
    }
    if (route === 'POST /login') {
      if (b.role === 'admin') {
        if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) return send(500, { error: 'ADMIN_USER and ADMIN_PASS are not set' });
        if (!(same(b.user, process.env.ADMIN_USER) && same(b.password, process.env.ADMIN_PASS))) return send(401, { error: 'Wrong username or password' });
        return send(200, { token: sign({ r: 'admin' }), role: 'admin', name: 'Admin' });
      }
      const r = (await sql`select id,name,pw from members where sn=${str(b.user, 30)}`)[0];
      if (!r || !checkPw(String(b.password || ''), r.pw)) return send(401, { error: 'Wrong student number or password' });
      return send(200, { token: sign({ r: 'member', id: r.id }), role: 'member', name: r.name });
    }

    const a = verify((req.headers.authorization || '').slice(7));
    if (!a) return send(401, { error: 'Please sign in again' });

    if (a.r === 'member') {
      const d = await today();
      if (route === 'GET /me') {
        const mem = (await sql`select id,sn,name,contact,course,year,section,status from members where id=${a.id}`)[0];
        if (!mem) return send(401, { error: 'Account not found' });
        const cnt = await sql`select status, count(*)::int n from attendance where member_id=${a.id} group by status`;
        const h = await sql`select to_char(day,'YYYY-MM-DD') day, status from attendance where member_id=${a.id} order by day desc limit 60`;
        const c = (await sql`select open from checkin where day=${d}::date`)[0];
        return send(200, { m: mem, counts: Object.fromEntries(cnt.map((x) => [x.status, x.n])), hist: h, open: !!c?.open, mine: h.find((x) => x.day === d)?.status || null });
      }
      if (route === 'POST /checkin') {
        const mem = (await sql`select status from members where id=${a.id}`)[0];
        if (mem?.status !== 'enrolled') return send(403, { error: 'Your enrollment is not approved yet' });
        const c = (await sql`select code,open from checkin where day=${d}::date`)[0];
        if (!c?.open || String(b.code).trim() !== c.code) return send(400, { error: 'Wrong code. Check with your teacher.' });
        await sql`insert into attendance(member_id,day,status) values(${a.id},${d}::date,'P') on conflict(member_id,day) do update set status='P'`;
        return send(200, { ok: true });
      }
      return send(404, { error: 'Not found' });
    }

    if (a.r !== 'admin') return send(403, { error: 'Forbidden' });
    const mm = p.match(/^\/members\/(\d+)$/), id = mm ? +mm[1] : 0;

    if (route === 'GET /members') {
      return send(200, await sql`select m.id,m.sn,m.name,m.contact,m.course,m.year,m.section,m.status,
        count(*) filter (where a.status='P')::int p, count(*) filter (where a.status='L')::int l,
        count(*) filter (where a.status='A')::int a, count(*) filter (where a.status='E')::int e
        from members m left join attendance a on a.member_id=m.id group by m.id order by m.name`);
    }
    if (route === 'POST /members') {
      const sn = str(b.sn, 30), name = str(b.name, 80), year = parseInt(b.year, 10), pw = String(b.password || sn);
      if (!sn || !name || !str(b.course) || !str(b.section) || !(year >= 1 && year <= 5)) return send(400, { error: 'Fill in all required fields' });
      if ((await sql`select 1 from members where sn=${sn}`).length) return send(409, { error: 'Student number already exists' });
      await sql`insert into members(sn,name,pw,contact,course,year,section,status) values(${sn},${name},${hashPw(pw)},${str(b.contact, 40)},${str(b.course, 20).toUpperCase()},${year},${str(b.section, 10).toUpperCase()},'enrolled')`;
      return send(201, { ok: true });
    }
    if (mm && m === 'PATCH') {
      if (b.status && !['pending', 'enrolled', 'rejected'].includes(b.status)) return send(400, { error: 'Invalid status' });
      await sql`update members set status=coalesce(${b.status ?? null},status), name=coalesce(${b.name ?? null},name), course=coalesce(${b.course ?? null},course), year=coalesce(${b.year ?? null}::int,year), section=coalesce(${b.section ?? null},section), contact=coalesce(${b.contact ?? null},contact) where id=${id}`;
      if (b.password) await sql`update members set pw=${hashPw(String(b.password))} where id=${id}`;
      return send(200, { ok: true });
    }
    if (mm && m === 'DELETE') { await sql`delete from members where id=${id}`; return send(200, { ok: true }); }

    if (route === 'GET /attendance') {
      const d = isDay(u.searchParams.get('date')) ? u.searchParams.get('date') : await today();
      return send(200, await sql`select m.id,m.sn,m.name,m.course,m.year,m.section,a.status from members m left join attendance a on a.member_id=m.id and a.day=${d}::date where m.status='enrolled' order by m.name`);
    }
    if (route === 'PUT /attendance') {
      const ids = (b.ids || []).map(Number).filter(Boolean);
      if (!isDay(b.day) || !ST.includes(b.status) || !ids.length) return send(400, { error: 'Invalid attendance data' });
      await sql`insert into attendance(member_id,day,status) select unnest(${ids}::int[]), ${b.day}::date, ${b.status} on conflict(member_id,day) do update set status=excluded.status`;
      return send(200, { ok: true });
    }
    if (route === 'GET /code') {
      const d = await today(), c = (await sql`select code,open from checkin where day=${d}::date`)[0];
      return send(200, { day: d, code: c?.code || null, open: !!c?.open });
    }
    if (route === 'POST /code') {
      const d = await today();
      if (b.open) await sql`insert into checkin(day,code,open) values(${d}::date,${String(Math.floor(1000 + Math.random() * 9000))},true) on conflict(day) do update set open=true`;
      else await sql`update checkin set open=false where day=${d}::date`;
      const c = (await sql`select code,open from checkin where day=${d}::date`)[0];
      return send(200, { day: d, code: c?.code || null, open: !!c?.open });
    }
    return send(404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    return send(500, { error: 'Server error' });
  }
}
