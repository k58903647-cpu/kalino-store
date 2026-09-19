import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_IN_PRODUCTION';
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'CHANGE_THIS_SECRET_IN_PRODUCTION') { throw new Error('JWT_SECRET must be set in production'); }
const ADMIN_EMAIL=process.env.ADMIN_EMAIL||'admin@kalino.ir';
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'Kalino@12345';
fs.mkdirSync(path.join(__dirname,'data'),{recursive:true}); fs.mkdirSync(path.join(__dirname,'uploads'),{recursive:true});
const db=new Database(path.join(__dirname,'data/kalino.db'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT UNIQUE,password TEXT,role TEXT DEFAULT 'customer',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT DEFAULT '',price INTEGER NOT NULL,old_price INTEGER DEFAULT 0,stock INTEGER DEFAULT 0,category TEXT DEFAULT 'لوازم جانبی موبایل',image TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,phone TEXT,address TEXT,total INTEGER,status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER,product_id INTEGER,title TEXT,price INTEGER,qty INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);`);
const adminHash=bcrypt.hashSync(ADMIN_PASSWORD,10);
const existing=db.prepare('SELECT id FROM users WHERE email=?').get(ADMIN_EMAIL);
if(!existing) db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)').run('مدیر کالینو',ADMIN_EMAIL,adminHash,'admin');
const count=db.prepare('SELECT COUNT(*) c FROM products').get().c;
if(!count){ const ins=db.prepare('INSERT INTO products(title,description,price,old_price,stock,category,image) VALUES(?,?,?,?,?,?,?)');
[['پاوربانک بوکو مدل MG-G134 ظرفیت 20000 میلی‌آمپر','پاوربانک 20000mAh با توان خروجی 22.5 وات و کابل USB-C همراه.',3750000,3990000,10,'پاوربانک',''],['کابل تبدیل USB-C بوکو مدل DIA-110 طول 1 متر','کابل تبدیل USB-C مناسب شارژ و انتقال داده.',450000,0,20,'کابل',''],['کابل USB-C یوشیتا مدل YC-058 طول 2 متر','کابل دو متری USB-C برای شارژ و انتقال داده.',520000,0,15,'کابل','']].forEach(p=>ins.run(...p)); }
function auth(req,res,next){try{const t=req.cookies.token;if(!t) return res.status(401).json({error:'ورود لازم است'}); req.user=jwt.verify(t,JWT_SECRET); next()}catch{return res.status(401).json({error:'نشست منقضی شده'})}}
function admin(req,res,next){auth(req,res,()=>req.user.role==='admin'?next():res.status(403).json({error:'دسترسی مدیر لازم است'}))}
app.use(express.json({limit:'2mb'})); app.use(cookieParser()); app.use('/uploads',express.static(path.join(__dirname,'uploads'))); app.use(express.static(path.join(__dirname,'public')));
const upload=multer({storage:multer.diskStorage({destination:path.join(__dirname,'uploads'),filename:(r,f)=>Date.now()+'-'+Math.random().toString(36).slice(2)+path.extname(f.originalname)}) ,limits:{fileSize:5*1024*1024}});
app.get('/health',(req,res)=>res.json({ok:true,service:'kalino'}));
app.get('/api/products',(req,res)=>{const q=(req.query.q||'').trim();const cat=req.query.category||'';let sql='SELECT * FROM products WHERE active=1';const args=[];if(q){sql+=' AND (title LIKE ? OR description LIKE ?)';args.push('%'+q+'%','%'+q+'%')}if(cat){sql+=' AND category=?';args.push(cat)}sql+=' ORDER BY id DESC';res.json(db.prepare(sql).all(...args))});
app.get('/api/categories',(req,res)=>res.json(db.prepare('SELECT category,COUNT(*) count FROM products WHERE active=1 GROUP BY category ORDER BY category').all()));
app.post('/api/auth/register',async(req,res)=>{const {name,email,password}=req.body;if(!name||!email||!password||password.length<6)return res.status(400).json({error:'نام، ایمیل و رمز حداقل ۶ حرفی لازم است'});try{const hash=await bcrypt.hash(password,10);const r=db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(name,email,hash);const u={id:r.lastInsertRowid,name,email,role:'customer'};res.cookie('token',jwt.sign(u,JWT_SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:604800000});res.json(u)}catch{res.status(409).json({error:'این ایمیل قبلاً ثبت شده است'})}});
app.post('/api/auth/login',async(req,res)=>{const {email,password}=req.body;const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u||!(await bcrypt.compare(password,u.password)))return res.status(401).json({error:'ایمیل یا رمز اشتباه است'});const safe={id:u.id,name:u.name,email:u.email,role:u.role};res.cookie('token',jwt.sign(safe,JWT_SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:604800000});res.json(safe)});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('token');res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json(req.user));
app.post('/api/orders',auth,(req,res)=>{const {name,phone,address,items}=req.body;if(!name||!phone||!address||!Array.isArray(items)||!items.length)return res.status(400).json({error:'اطلاعات سفارش کامل نیست'});let total=0;const rows=[];for(const i of items){const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(i.product_id);const qty=Math.max(1,Number(i.qty)||1);if(!p||p.stock<qty)return res.status(400).json({error:`موجودی «${p?.title||'کالا'}» کافی نیست`});total+=p.price*qty;rows.push({p,qty})}const tx=db.transaction(()=>{const r=db.prepare('INSERT INTO orders(user_id,name,phone,address,total) VALUES(?,?,?,?,?)').run(req.user.id,name,phone,address,total);const oi=db.prepare('INSERT INTO order_items(order_id,product_id,title,price,qty) VALUES(?,?,?,?,?)');const up=db.prepare('UPDATE products SET stock=stock-? WHERE id=?');rows.forEach(x=>{oi.run(r.lastInsertRowid,x.p.id,x.p.title,x.p.price,x.qty);up.run(x.qty,x.p.id)});return r.lastInsertRowid});res.json({id:tx(),total})});
app.get('/api/orders',auth,(req,res)=>res.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.get('/api/admin/stats',admin,(req,res)=>res.json({products:db.prepare('SELECT COUNT(*) c FROM products').get().c,orders:db.prepare('SELECT COUNT(*) c FROM orders').get().c,revenue:db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE status!='cancelled'").get().s,customers:db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,lowStock:db.prepare('SELECT COUNT(*) c FROM products WHERE stock<=3').get().c}));
app.get('/api/admin/products',admin,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products',admin,(req,res)=>{const {title,description,price,old_price,stock,category,image,active=1}=req.body;if(!title||Number(price)<0)return res.status(400).json({error:'عنوان و قیمت لازم است'});const r=db.prepare('INSERT INTO products(title,description,price,old_price,stock,category,image,active) VALUES(?,?,?,?,?,?,?,?)').run(title,description||'',Number(price),Number(old_price)||0,Number(stock)||0,category||'لوازم جانبی موبایل',image||'',active?1:0);res.json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid))});
app.put('/api/admin/products/:id',admin,(req,res)=>{const {title,description,price,old_price,stock,category,image,active}=req.body;db.prepare('UPDATE products SET title=?,description=?,price=?,old_price=?,stock=?,category=?,image=?,active=? WHERE id=?').run(title,description||'',Number(price),Number(old_price)||0,Number(stock)||0,category||'',image||'',active?1:0,req.params.id);res.json(db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id))});
app.delete('/api/admin/products/:id',admin,(req,res)=>{db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);res.json({ok:true})});
app.post('/api/admin/upload',admin,upload.single('image'),(req,res)=>res.json({url:'/uploads/'+req.file.filename}));
app.get('/api/admin/orders',admin,(req,res)=>res.json(db.prepare('SELECT o.*,u.email FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC').all()));
app.put('/api/admin/orders/:id',admin,(req,res)=>{db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,req.params.id);res.json({ok:true})});
app.get('/api/admin/users',admin,(req,res)=>res.json(db.prepare('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC').all()));
app.get('/api/settings',(req,res)=>{const rows=db.prepare('SELECT * FROM settings').all();res.json(Object.fromEntries(rows.map(x=>[x.key,x.value])))});
app.put('/api/admin/settings',admin,(req,res)=>{const st=db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');for(const [k,v] of Object.entries(req.body))st.run(k,String(v));res.json({ok:true})});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`Kalino running on http://localhost:${PORT}`));
