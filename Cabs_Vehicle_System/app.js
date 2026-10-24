const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const conn = require('./conn');
const app = express();

/* ---------------- SETUP ---------------- */

app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({extended:true}));
app.use(session({
    // set SESSION_SECRET in your environment for real use
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave:false,
    saveUninitialized:false,
    cookie:{ httpOnly:true, sameSite:'lax', maxAge: 8*60*60*1000 }   // 8 hours
}));
app.use((req,res,next)=>{
    res.set('X-Content-Type-Options','nosniff');
    res.set('X-Frame-Options','DENY');
    next();
});

// date shown in every page, e.g. <%= fmt(data.log_time) %>
app.locals.fmt = (d)=> d ? new Date(d).toLocaleString('en-PH') : '-';

/* ---------------- HELPERS ---------------- */

// run a query and get a promise (so we can use async/await)
function q(sql, params){
    return new Promise((resolve,reject)=>{
        conn.query(sql, params || [], (err,rows)=> err ? reject(err) : resolve(rows));
    });
}

// any error inside a route goes to the error handler at the bottom
// instead of crashing the whole server
const wrap = (fn)=> (req,res,next)=> Promise.resolve(fn(req,res,next)).catch(next);

// show an alert then go to another page
function alertGo(res, msg, url){
    const safe = (s)=> JSON.stringify(s).replace(/</g,'\\u003c');
    res.send(`<script>alert(${safe(msg)}); location.href = ${safe(url)};</script>`);
}

const HOME = { student:'/student', guard:'/guard', admin:'/admin' };

// only let a certain role open a page.
// POST requests must also carry the session's secret token (CSRF protection)
function onlyFor(role){
    return (req,res,next)=>{
        const u = req.session.user;
        if(!u || u.role !== role){
            return alertGo(res,'PLEASE LOGIN FIRST!','/');
        }
        if(req.method === 'POST' && req.body._csrf !== req.session.csrf){
            return alertGo(res,'INVALID REQUEST. PLEASE TRY AGAIN.', HOME[role]);
        }
        res.locals.user = u;
        res.locals.csrf = req.session.csrf;
        next();
    };
}

// "abc 123" / "ABC-123" -> "ABC123"
const cleanPlate = (s)=> String(s || '').toUpperCase().replace(/[^A-Z0-9]/g,'');
const clean = (s,max)=> String(s || '').trim().slice(0,max);

// last gate action of a registered vehicle: 'ENTRY', 'EXIT' or null
async function lastActionOf(vehicleId){
    const r = await q(`SELECT action FROM tbl_gate_logs WHERE vehicle_id = ? ORDER BY idnum DESC LIMIT 1`,[vehicleId]);
    return r.length > 0 ? r[0].action : null;
}

// only allow going back to a guard page (never to another website)
function safeBack(url, fallback){
    url = String(url || '');
    return (url.startsWith('/guard') && !url.startsWith('//')) ? url : fallback;
}

// reused inside several queries (v = tbl_vehicles)
const LAST_ACTION = `(SELECT action FROM tbl_gate_logs WHERE vehicle_id = v.idnum ORDER BY idnum DESC LIMIT 1)`;
const LAST_TIME   = `(SELECT log_time FROM tbl_gate_logs WHERE vehicle_id = v.idnum ORDER BY idnum DESC LIMIT 1)`;

/* ---------------- LOGIN / SIGNUP ---------------- */

// block brute-force guessing: 5 wrong tries per email+IP, then wait 10 minutes
const attempts = {};
function isLocked(key){
    const a = attempts[key];
    return a && a.n >= 5 && Date.now() < a.until;
}
function addFail(key){
    let a = attempts[key];
    if(!a || Date.now() >= a.until) a = attempts[key] = {n:0, until: Date.now() + 10*60*1000};
    a.n++;
}

app.get('/', (req,res)=>{
    res.render('login');
});

app.get('/signup', (req,res)=>{
    res.render('signup');
});

// student creates an account
app.post('/register', wrap(async (req,res)=>{
    const fullname = clean(req.body.fullname,100);
    const email = clean(req.body.email,100).toLowerCase();
    const pw = String(req.body.pw || '');

    if(fullname.length < 2) return alertGo(res,'PLEASE ENTER YOUR FULL NAME!','/signup');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return alertGo(res,'INVALID EMAIL!','/signup');
    if(pw.length < 6 || pw.length > 72) return alertGo(res,'PASSWORD MUST BE 6 TO 72 CHARACTERS!','/signup');

    const hash = await bcrypt.hash(pw,10);

    try{
        await q(`INSERT INTO tbl_users (fullname,email,password,role) VALUES(?,?,?,'student')`,[fullname,email,hash]);
    }catch(err){
        if(err.code === 'ER_DUP_ENTRY') return alertGo(res,'EMAIL ALREADY USED!','/signup');
        throw err;
    }
    alertGo(res,'ACCOUNT CREATED! PLEASE LOGIN.','/');
}));

app.post('/login', wrap(async (req,res)=>{
    const email = clean(req.body.email,100).toLowerCase();
    const pw = String(req.body.pw || '');
    const key = req.ip + '|' + email;

    if(isLocked(key)) return alertGo(res,'TOO MANY WRONG TRIES. WAIT 10 MINUTES.','/');

    const result = await q(`SELECT * FROM tbl_users WHERE email = ?`,[email]);
    let ok = false;

    if(result.length > 0){
        const u = result[0];
        if(u.password.startsWith('$2')){
            ok = await bcrypt.compare(pw,u.password);
        }else if(u.password === pw){
            // account from the old version (plain text): accept once, then store a hash
            ok = true;
            await q(`UPDATE tbl_users SET password = ? WHERE idnum = ?`,[await bcrypt.hash(pw,10),u.idnum]);
        }
    }

    if(!ok){
        addFail(key);
        return alertGo(res,'WRONG EMAIL OR PASSWORD!','/');
    }
    delete attempts[key];

    const u = result[0];

    // brand new session id after login (prevents session fixation)
    await new Promise((resolve,reject)=> req.session.regenerate((e)=> e ? reject(e) : resolve()));
    req.session.user = {idnum:u.idnum, fullname:u.fullname, role:u.role};
    req.session.csrf = crypto.randomBytes(24).toString('hex');

    res.redirect(HOME[u.role] || '/student');
}));

app.post('/logout', (req,res)=>{
    if(req.session.user && req.body._csrf !== req.session.csrf){
        return alertGo(res,'INVALID REQUEST. PLEASE TRY AGAIN.', HOME[req.session.user.role]);
    }
    req.session.destroy(()=>{
        res.redirect('/');
    });
});

/* ---------------- STUDENT ---------------- */

// register vehicle form + own vehicles (status and inside/outside)
app.get('/student', onlyFor('student'), wrap(async (req,res)=>{
    const result = await q(`SELECT v.*, ${LAST_ACTION} AS last_action
                            FROM tbl_vehicles v WHERE v.owner_id = ? ORDER BY v.idnum DESC`,
                           [req.session.user.idnum]);
    res.render('student',{ vehicle: result });
}));

app.post('/vehicle', onlyFor('student'), wrap(async (req,res)=>{
    const plate = cleanPlate(req.body.plate);
    const type = clean(req.body.type,30);
    const brand = clean(req.body.brand,50);
    const color = clean(req.body.color,30);

    if(!/^[A-Z0-9]{2,12}$/.test(plate)) return alertGo(res,'INVALID PLATE NUMBER! USE LETTERS AND NUMBERS ONLY.','/student');
    if(!['Car','Motorcycle','Tricycle','Other'].includes(type)) return alertGo(res,'PLEASE CHOOSE A VEHICLE TYPE!','/student');
    if(brand === '' || color === '') return alertGo(res,'PLEASE FILL IN ALL FIELDS!','/student');

    try{
        await q(`INSERT INTO tbl_vehicles (owner_id,plate,type,brand,color) VALUES(?,?,?,?,?)`,
                [req.session.user.idnum,plate,type,brand,color]);
    }catch(err){
        if(err.code === 'ER_DUP_ENTRY') return alertGo(res,'PLATE NUMBER ALREADY REGISTERED!','/student');
        throw err;
    }
    alertGo(res,'VEHICLE SUBMITTED! WAIT FOR APPROVAL.','/student');
}));

// student's own in/out history (only their own vehicles)
app.get('/student/history', onlyFor('student'), wrap(async (req,res)=>{
    const me = req.session.user.idnum;
    const mine = await q(`SELECT idnum, plate FROM tbl_vehicles WHERE owner_id = ? ORDER BY plate`,[me]);

    const pick = parseInt(req.query.vehicle,10) || 0;
    let sql = `SELECT l.action, l.log_time, v.plate, g.fullname AS guard
               FROM tbl_gate_logs l
               JOIN tbl_vehicles v ON l.vehicle_id = v.idnum
               JOIN tbl_users g ON l.guard_id = g.idnum
               WHERE v.owner_id = ?`;
    const params = [me];
    if(pick){ sql += ` AND v.idnum = ?`; params.push(pick); }
    sql += ` ORDER BY l.idnum DESC LIMIT 200`;

    const logs = await q(sql,params);
    res.render('student_history',{ mine, pick, logs });
}));

/* ---------------- ADMIN ---------------- */

app.get('/admin', onlyFor('admin'), wrap(async (req,res)=>{
    const result = await q(`SELECT v.*, u.fullname, ${LAST_ACTION} AS last_action
                            FROM tbl_vehicles v
                            JOIN tbl_users u ON v.owner_id = u.idnum
                            ORDER BY FIELD(v.status,'Pending','Approved','Rejected'), v.idnum DESC`);
    res.render('admin',{ vehicle: result });
}));

app.post('/review', onlyFor('admin'), wrap(async (req,res)=>{
    const id = parseInt(req.body.id,10);
    const status = req.body.status;

    if(status !== 'Approved' && status !== 'Rejected'){
        return alertGo(res,'INVALID STATUS!','/admin');
    }

    const found = await q(`SELECT idnum FROM tbl_vehicles WHERE idnum = ?`,[id]);
    if(found.length === 0) return alertGo(res,'VEHICLE NOT FOUND!','/admin');

    // a car that is inside must be logged out first, otherwise it would be stuck "inside"
    if(await lastActionOf(id) === 'ENTRY'){
        return alertGo(res,'VEHICLE IS CURRENTLY INSIDE. RECORD ITS EXIT FIRST.','/admin');
    }

    await q(`UPDATE tbl_vehicles SET status = ? WHERE idnum = ?`,[status,id]);
    alertGo(res,'VEHICLE ' + status.toUpperCase() + '!','/admin');
}));

/* ----- admin: full gate history (registered + visitors) with filters ----- */

// registered ENTRY/EXIT and visitor IN/OUT merged into one list of events
const HISTORY_SQL = `
    SELECT * FROM (
        SELECT l.log_time AS ts, 'Registered' AS kind, v.plate AS plate, u.fullname AS who,
               l.action AS action, g.fullname AS guard, CONCAT(v.color,' ',v.brand,' (',v.type,')') AS details
        FROM tbl_gate_logs l
        JOIN tbl_vehicles v ON l.vehicle_id = v.idnum
        JOIN tbl_users u ON v.owner_id = u.idnum
        JOIN tbl_users g ON l.guard_id = g.idnum

        UNION ALL

        SELECT x.time_in, 'Visitor', x.plate, x.visitor_name, 'ENTRY', g.fullname,
               CONCAT('Visiting ',x.person_visited,' | ',x.purpose,' | ID: ',x.id_shown,' | Contact: ',x.contact)
        FROM tbl_visitor_logs x
        JOIN tbl_users g ON x.guard_in = g.idnum

        UNION ALL

        SELECT x.time_out, 'Visitor', x.plate, x.visitor_name, 'EXIT', g.fullname,
               CONCAT('Visiting ',x.person_visited,' | ',x.purpose,' | ID: ',x.id_shown,' | Contact: ',x.contact)
        FROM tbl_visitor_logs x
        JOIN tbl_users g ON x.guard_out = g.idnum
        WHERE x.time_out IS NOT NULL
    ) t`;

// read the filters from the URL and build the WHERE part
function historyFilter(qs){
    const where = [];
    const params = [];
    const f = {
        type:   ['Registered','Visitor'].includes(qs.type) ? qs.type : '',
        action: ['ENTRY','EXIT'].includes(qs.action) ? qs.action : '',
        from:   /^\d{4}-\d{2}-\d{2}$/.test(qs.from || '') ? qs.from : '',
        to:     /^\d{4}-\d{2}-\d{2}$/.test(qs.to || '') ? qs.to : '',
        q:      clean(qs.q,50)
    };

    if(f.type){   where.push(`kind = ?`);        params.push(f.type); }
    if(f.action){ where.push(`action = ?`);      params.push(f.action); }
    if(f.from){   where.push(`DATE(ts) >= ?`);   params.push(f.from); }
    if(f.to){     where.push(`DATE(ts) <= ?`);   params.push(f.to); }
    if(f.q){
        where.push(`(plate LIKE ? OR who LIKE ?)`);
        params.push('%' + (cleanPlate(f.q) || f.q) + '%', '%' + f.q + '%');
    }

    return { f, sql: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
}

app.get('/admin/history', onlyFor('admin'), wrap(async (req,res)=>{
    const h = historyFilter(req.query);
    const logs = await q(HISTORY_SQL + h.sql + ` ORDER BY ts DESC LIMIT 500`, h.params);
    res.render('admin_history',{ logs, f:h.f, qs: new URLSearchParams(h.f).toString() });
}));

// same filters, downloaded as a CSV file (opens in Excel)
app.get('/admin/history.csv', onlyFor('admin'), wrap(async (req,res)=>{
    const h = historyFilter(req.query);
    const logs = await q(HISTORY_SQL + h.sql + ` ORDER BY ts DESC LIMIT 50000`, h.params);

    // quote every cell; a leading = + - @ is neutralised so Excel never runs it as a formula
    const cell = (v)=>{
        let s = String(v === null || v === undefined ? '' : v);
        if(/^[=+\-@\t\r]/.test(s)) s = "'" + s;
        return '"' + s.replace(/"/g,'""') + '"';
    };
    const pad = (n)=> String(n).padStart(2,'0');
    const stamp = (d)=>{
        d = new Date(d);
        return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
    };

    const lines = [['Date & Time','Type','Plate','Name','Action','Guard','Details'].map(cell).join(',')];
    logs.forEach((r)=>{
        lines.push([stamp(r.ts), r.kind, r.plate, r.who, r.action, r.guard, r.details].map(cell).join(','));
    });

    res.set('Content-Type','text/csv; charset=utf-8');
    res.set('Content-Disposition','attachment; filename="gate-history-' + new Date().toISOString().slice(0,10) + '.csv"');
    res.send('\ufeff' + lines.join('\r\n'));
}));

// who is inside the campus right now
app.get('/admin/inside', onlyFor('admin'), wrap(async (req,res)=>{
    const cars = await q(`SELECT v.plate, v.type, v.brand, v.color, u.fullname, l.log_time
                          FROM tbl_vehicles v
                          JOIN tbl_users u ON v.owner_id = u.idnum
                          JOIN tbl_gate_logs l ON l.idnum = (SELECT MAX(idnum) FROM tbl_gate_logs WHERE vehicle_id = v.idnum)
                          WHERE l.action = 'ENTRY'
                          ORDER BY l.log_time DESC`);
    const visitors = await q(`SELECT x.*, g.fullname AS guard
                              FROM tbl_visitor_logs x
                              JOIN tbl_users g ON x.guard_in = g.idnum
                              WHERE x.time_out IS NULL
                              ORDER BY x.time_in DESC`);
    res.render('admin_inside',{ cars, visitors });
}));

/* ---------------- SECURITY GUARD ---------------- */

// search plate number, check approval, show recent gate logs
app.get('/guard', onlyFor('guard'), wrap(async (req,res)=>{
    const plate = cleanPlate(req.query.plate);

    const logs = await q(`SELECT l.*, v.plate
                          FROM tbl_gate_logs l
                          JOIN tbl_vehicles v ON l.vehicle_id = v.idnum
                          ORDER BY l.idnum DESC LIMIT 10`);

    let vehicle = null;
    let lastAction = null;

    if(plate !== ''){
        const result = await q(`SELECT v.*, u.fullname
                                FROM tbl_vehicles v
                                JOIN tbl_users u ON v.owner_id = u.idnum
                                WHERE v.plate = ?`,[plate]);
        if(result.length > 0){
            vehicle = result[0];
            lastAction = await lastActionOf(vehicle.idnum);
        }
    }

    res.render('guard',{
        plate, searched: plate !== '', vehicle, lastAction, logs,
        back: '/guard?plate=' + encodeURIComponent(plate)
    });
}));

// list of registered (approved) vehicles, with inside/outside and quick buttons
app.get('/guard/vehicles', onlyFor('guard'), wrap(async (req,res)=>{
    const search = clean(req.query.q,50);
    const loc = ['INSIDE','OUTSIDE'].includes(req.query.loc) ? req.query.loc : '';

    let sql = `SELECT v.idnum, v.plate, v.type, v.brand, v.color, u.fullname,
                      ${LAST_ACTION} AS last_action, ${LAST_TIME} AS last_time
               FROM tbl_vehicles v
               JOIN tbl_users u ON v.owner_id = u.idnum
               WHERE v.status = 'Approved'`;
    const params = [];
    if(search){
        sql += ` AND (v.plate LIKE ? OR u.fullname LIKE ? OR v.brand LIKE ?)`;
        params.push('%' + (cleanPlate(search) || search) + '%', '%' + search + '%', '%' + search + '%');
    }
    sql += ` ORDER BY u.fullname, v.plate LIMIT 500`;

    let vehicles = await q(sql,params);
    const insideCount = vehicles.filter((v)=> v.last_action === 'ENTRY').length;
    if(loc === 'INSIDE')  vehicles = vehicles.filter((v)=> v.last_action === 'ENTRY');
    if(loc === 'OUTSIDE') vehicles = vehicles.filter((v)=> v.last_action !== 'ENTRY');

    res.render('guard_vehicles',{
        vehicles, search, loc, insideCount,
        back: '/guard/vehicles?' + new URLSearchParams({q:search, loc}).toString()
    });
}));

// record entry or exit of a registered vehicle
app.post('/gate', onlyFor('guard'), wrap(async (req,res)=>{
    const id = parseInt(req.body.id,10);
    const action = req.body.action;
    const back = safeBack(req.body.back,'/guard');

    if(action !== 'ENTRY' && action !== 'EXIT'){
        return alertGo(res,'INVALID ACTION!',back);
    }

    const result = await q(`SELECT plate, status FROM tbl_vehicles WHERE idnum = ?`,[id]);
    if(result.length === 0){
        return alertGo(res,'VEHICLE NOT FOUND!',back);
    }

    const lastAction = await lastActionOf(id);

    if(action === 'ENTRY'){
        // only approved vehicles may come in
        if(result[0].status !== 'Approved') return alertGo(res,'VEHICLE IS NOT APPROVED!',back);
        if(lastAction === 'ENTRY')          return alertGo(res,'VEHICLE IS ALREADY INSIDE!',back);
    }else{
        // a vehicle that is inside can ALWAYS leave, whatever its status is now
        if(lastAction !== 'ENTRY')          return alertGo(res,'VEHICLE IS NOT INSIDE!',back);
    }

    await q(`INSERT INTO tbl_gate_logs (vehicle_id,guard_id,action) VALUES(?,?,?)`,[id,req.session.user.idnum,action]);
    alertGo(res,action + ' RECORDED!',back);
}));

/* ----- visitor logbook (cars that are not registered) ----- */

const ID_TYPES = ["Driver's License","Passport","UMID","National ID","Company ID","Other Government ID","Other"];

app.get('/guard/visitors', onlyFor('guard'), wrap(async (req,res)=>{
    const inside = await q(`SELECT * FROM tbl_visitor_logs WHERE time_out IS NULL ORDER BY time_in DESC`);
    const recent = await q(`SELECT * FROM tbl_visitor_logs WHERE time_out IS NOT NULL ORDER BY time_out DESC LIMIT 20`);
    res.render('guard_visitors',{ inside, recent, idTypes: ID_TYPES });
}));

app.post('/visitor/in', onlyFor('guard'), wrap(async (req,res)=>{
    const back = '/guard/visitors';
    const name    = clean(req.body.visitor_name,100);
    const plate   = cleanPlate(req.body.plate);
    const idShown = clean(req.body.id_shown,50);
    const contact = clean(req.body.contact,30);
    const visited = clean(req.body.person_visited,100);
    const purpose = clean(req.body.purpose,150);

    if(name === '' || visited === '' || purpose === '') return alertGo(res,'PLEASE FILL IN ALL FIELDS!',back);
    if(!/^[A-Z0-9]{2,12}$/.test(plate))                 return alertGo(res,'INVALID PLATE NUMBER!',back);
    if(!ID_TYPES.includes(idShown))                     return alertGo(res,'PLEASE CHOOSE THE ID SHOWN!',back);
    if(!/^[0-9+\-\s()]{7,30}$/.test(contact))           return alertGo(res,'INVALID CONTACT NUMBER!',back);

    // a registered car must use the normal gate check, not the visitor book
    const reg = await q(`SELECT idnum FROM tbl_vehicles WHERE plate = ?`,[plate]);
    if(reg.length > 0) return alertGo(res,'THIS PLATE IS A REGISTERED VEHICLE. USE GATE CHECK INSTEAD.','/guard?plate=' + encodeURIComponent(plate));

    const already = await q(`SELECT idnum FROM tbl_visitor_logs WHERE plate = ? AND time_out IS NULL`,[plate]);
    if(already.length > 0) return alertGo(res,'THIS VISITOR VEHICLE IS ALREADY INSIDE!',back);

    await q(`INSERT INTO tbl_visitor_logs (visitor_name,plate,id_shown,contact,person_visited,purpose,guard_in)
             VALUES(?,?,?,?,?,?,?)`,
            [name,plate,idShown,contact,visited,purpose,req.session.user.idnum]);
    alertGo(res,'VISITOR TIME IN RECORDED!',back);
}));

app.post('/visitor/out', onlyFor('guard'), wrap(async (req,res)=>{
    const id = parseInt(req.body.id,10);
    const result = await q(`UPDATE tbl_visitor_logs SET time_out = NOW(), guard_out = ?
                            WHERE idnum = ? AND time_out IS NULL`,[req.session.user.idnum,id]);

    if(result.affectedRows === 0) return alertGo(res,'VISITOR IS NOT INSIDE!','/guard/visitors');
    alertGo(res,'VISITOR TIME OUT RECORDED!','/guard/visitors');
}));

/* ---------------- ERRORS ---------------- */

app.use((req,res)=>{
    res.status(404).send('<h3>Page not found</h3><a href="/">Go back</a>');
});

app.use((err,req,res,next)=>{
    console.error(err);
    if(res.headersSent) return next(err);
    res.status(500).send('<h3>Something went wrong. Please try again.</h3><a href="/">Go back</a>');
});

app.listen(5000, ()=> console.log('CABS running at http://localhost:5000'));
