import glob
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", HERE)            # مكان حفظ قاعدة البيانات والصور
UP = os.path.join(DATA, "uploads")
os.makedirs(UP, exist_ok=True)
DB = os.path.join(DATA, "store.db")
WA = os.environ.get("STORE_WHATSAPP", "")          # مثال: 9647801234567
FEE = float(os.environ.get("DELIVERY_FEE", "0"))
CUR = os.environ.get("CURRENCY", "د.ع")
KEY = os.environ.get("ADMIN_KEY")                  # كلمة سر لوحة الإدارة
NAME = os.environ.get("STORE_NAME", "متجري")
TAGLINE = os.environ.get("STORE_TAGLINE", "اطلب الآن وادفع عند الاستلام")
LOW = int(os.environ.get("LOW_STOCK", "5"))      # حد التنبيه عند قرب نفاد المنتج
COLOR = os.environ.get("THEME_COLOR", "#1a7f5a")   # لون المتجر
EXT = {"png", "jpg", "jpeg", "webp", "gif"}

# إشعار واتساب تلقائي (WhatsApp Cloud API من Meta)
WA_TOKEN = os.environ.get("WA_TOKEN")                  # الرمز (Access Token)
WA_PHONE_ID = os.environ.get("WA_PHONE_ID")            # معرّف رقم الواتساب (Phone Number ID)
WA_TEMPLATE = os.environ.get("WA_TEMPLATE")            # اسم القالب المعتمد (مطلوب إذا مرّ 24 ساعة على آخر رسالة منك)
WA_TEMPLATE_LANG = os.environ.get("WA_TEMPLATE_LANG", "ar")
WA_API_VERSION = os.environ.get("WA_API_VERSION", "v23.0")
WA_STATE = {"ok": None, "err": ""}
A1 = os.environ.get("ACCENT", "#00e5ff")      # لون التمييز الأول (سماوي نيون)
A2 = os.environ.get("ACCENT2", "#a855f7")     # لون التمييز الثاني (بنفسجي)
app = Flask(__name__)
app.secret_key = hashlib.sha256(("store:" + (KEY or "")).encode()).hexdigest()
app.config.update(MAX_CONTENT_LENGTH=8 * 1024 * 1024, SESSION_COOKIE_SAMESITE="Lax")


def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = conn()
    c.executescript("""
    create table if not exists orders(id integer primary key, created text default current_timestamp,
        name text, phone text, city text, address text, notes text, items text, total real);
    create table if not exists users(id integer primary key, username text unique not null, pw text not null,
        role text default 'staff', perms text default '', active integer default 1);
    create table if not exists banners(id integer primary key, title text default '', subtitle text default '',
        image text default '', link text default '');
    create table if not exists products(id integer primary key, name text not null, price real not null,
        descr text default '', image text default '', category text default '', active integer default 1);""")
    c.executescript("""
    create table if not exists activity_logs(
        id integer primary key, created text default current_timestamp,
        user_id integer, username text, action text not null, details text default '',
        ip text default '', method text default '', path text default '');
    """)
    for q in ("alter table orders add column status text default 'new'",
              "alter table products add column badge text default ''",
              "alter table products add column stock integer",
              "alter table products add column items_json text",
              "alter table products add column purchase_price real default 0",
              "alter table orders add column items_snapshot text",
              "alter table orders add column items_subtotal real default 0",
              "alter table orders add column delivery_fee real default 0"):

        try:
            c.execute(q)
        except sqlite3.OperationalError:
            pass
    if KEY and not c.execute("select 1 from users").fetchone():   # المدير الأول: admin وكلمة سره = ADMIN_KEY
        c.execute("insert into users(username,pw,role) values('admin',?, 'owner')", (generate_password_hash(KEY),))
    old = os.path.join(HERE, "products.json")
    if not c.execute("select 1 from products").fetchone() and os.path.exists(old):
        for p in json.load(open(old, encoding="utf-8")):
            c.execute("insert into products(name,price,descr,category) values(?,?,?,?)",
                      (p["name"], p["price"], p.get("desc", ""), p.get("category", "")))
    c.commit()
    c.close()


def prods(only_active=True):
    c = conn()
    rows = c.execute("select * from products" + (" where active=1" if only_active else "") + " order by id desc")
    out = [{"id": r["id"], "name": r["name"], "price": r["price"], "desc": r["descr"],
            "image": r["image"], "category": r["category"], "active": r["active"], "badge": r["badge"] or "", "stock": r["stock"], "purchase_price": r["purchase_price"] or 0} for r in rows]
    c.close()
    return out


def banners():
    c = conn()
    r = [dict(x) for x in c.execute("select * from banners order by id desc")]
    c.close()
    return r


def logo():
    f = glob.glob(os.path.join(UP, "logo.*"))
    return f"/uploads/{os.path.basename(f[0])}?v={int(os.path.getmtime(f[0]))}" if f else ""


def save_img(f, name=None):
    if not f or not f.filename:
        return None
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in EXT:
        return None
    n = (name or secrets.token_hex(8)) + "." + ext
    f.save(os.path.join(UP, n))
    return n



def audit(action, details="", user=None):
    """يسجل العمليات الإدارية المهمة؛ سجل النشاط يبدأ من وقت تفعيل هذه النسخة."""
    try:
        user = user or me()
        uid = user["id"] if user else session.get("uid")
        username = user["username"] if user else ("زائر" if not uid else "مستخدم")
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or ""
        # لا نثق بترويسة IP المقدمة من العميل إلا إذا كان التطبيق خلف Cloudflare.
        if not request.headers.get("CF-Connecting-IP"):
            ip = request.remote_addr or ""
        c = conn()
        c.execute("insert into activity_logs(user_id,username,action,details,ip,method,path) values(?,?,?,?,?,?,?)",
                  (uid, username, str(action)[:100], str(details)[:1000], ip[:100], request.method, request.path[:300]))
        c.commit()
        c.close()
    except Exception as e:
        print("Activity log failed:", e)


def notify(msg):
    """يرسل تفاصيل الطلب لواتساب صاحب المتجر بالخلفية، وفشله ما يأثر على الطلب."""
    if not (WA_TOKEN and WA_PHONE_ID and WA):
        return

    def run():
        if WA_TEMPLATE:
            one = " | ".join(x for x in msg.split("\n") if x.strip())[:900]
            body = {"type": "template", "template": {"name": WA_TEMPLATE, "language": {"code": WA_TEMPLATE_LANG},
                    "components": [{"type": "body", "parameters": [{"type": "text", "text": one}]}]}}
        else:
            body = {"type": "text", "text": {"body": msg}}
        body.update(messaging_product="whatsapp", to=WA)
        try:
            req = urllib.request.Request(
                f"https://graph.facebook.com/{WA_API_VERSION}/{WA_PHONE_ID}/messages",
                data=json.dumps(body).encode(),
                headers={"Authorization": "Bearer " + WA_TOKEN, "Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=15).read()
            WA_STATE.update(ok=True, err="")
        except Exception as e:
            detail = e.read().decode()[:300] if hasattr(e, "read") else str(e)
            WA_STATE.update(ok=False, err=detail)
            print("WhatsApp notify failed:", detail)

    threading.Thread(target=run, daemon=True).start()


@app.get("/uploads/<path:n>")
def uploads(n):
    return send_from_directory(UP, n)


@app.get("/api/products")
def api_products():
    # لا نرسل سعر الشراء للواجهة العامة للزبون.
    public_products = [{k: v for k, v in p.items() if k != "purchase_price"} for p in prods()]
    return jsonify(products=public_products, fee=FEE, currency=CUR, name=NAME, tagline=TAGLINE, logo=logo(), banners=banners(), whatsapp=WA, low=LOW)


@app.post("/api/orders")
def api_order():
    j = request.get_json(force=True)
    P = {p["id"]: p for p in prods()}
    items = []
    try:
        for i in j["items"]:
            q = int(i["qty"])
            if not 1 <= q <= 99:
                raise ValueError
            items.append((P[int(i["id"])], q))
    except (KeyError, ValueError, TypeError):
        return jsonify(error="السلة غير صحيحة"), 400
    name, phone, city, address = [str(j.get(k, "")).strip()[:200] for k in ("name", "phone", "city", "address")]
    notes = str(j.get("notes", "")).strip()[:500]
    if not items or not (name and phone and city and address):
        return jsonify(error="عبّي كل المعلومات المطلوبة"), 400
    sub = sum(p["price"] * q for p, q in items)
    total = sub + FEE
    lines = "\n".join(f"- {p['name']} × {q} = {p['price'] * q:g} {CUR}" for p, q in items)
    subtotal = sum(p["price"] * q for p, q in items)
    snapshot = [{"id": p["id"], "name": p["name"], "qty": q,
                 "sale_price": float(p["price"]), "purchase_price": float(p.get("purchase_price") or 0),
                 "line_total": float(p["price"] * q)} for p, q in items]
    c = conn()
    for p, q in items:
        if p["stock"] is not None:
            cur = c.execute("update products set stock=stock-? where id=? and stock>=?", (q, p["id"], q))
            if cur.rowcount == 0:
                c.rollback()
                c.close()
                return jsonify(error=f"الكمية المتوفرة من «{p['name']}» غير كافية"), 400
    oid = c.execute("insert into orders(name,phone,city,address,notes,items,total,items_json,items_snapshot,items_subtotal,delivery_fee) values(?,?,?,?,?,?,?,?,?,?,?)",
                    (name, phone, city, address, notes, lines, total,
                     json.dumps([[p["id"], q] for p, q in items]), json.dumps(snapshot, ensure_ascii=False), subtotal, FEE)).lastrowid
    c.commit()
    c.close()
    audit("إنشاء طلب من المتجر", f"الطلب #{oid}؛ الإجمالي {total:g} {CUR}")
    msg = (f"🛒 طلب جديد #{oid}\n\nالاسم: {name}\nالهاتف: {phone}\nالمحافظة: {city}\n"
           f"العنوان: {address}\nملاحظات: {notes or '-'}\n\nالطلب:\n{lines}\n\n"
           f"المجموع: {sub:g} {CUR}\nالتوصيل: {FEE:g} {CUR}\nالإجمالي: {total:g} {CUR}\nالدفع: عند الاستلام")
    notify(msg)
    return jsonify(id=oid, total=total)


# ---------------- لوحة الإدارة ----------------
PERMS = ("orders", "products", "stock", "banners", "logo")
FAILS = {}


def me():
    uid = session.get("uid")
    if not uid:
        return None
    c = conn()
    u = c.execute("select * from users where id=? and active=1", (uid,)).fetchone()
    c.close()
    return u


def can(u, *perms):
    return bool(u) and (u["role"] == "owner" or not perms or any(p in (u["perms"] or "").split(",") for p in perms))


def need(*perms):
    if not can(me(), *perms):
        abort(403)


def owner():
    u = me()
    if not u or u["role"] != "owner":
        abort(403)


def uview(u):
    return {"id": u["id"], "username": u["username"], "role": u["role"], "active": u["active"],
            "perms": [p for p in (u["perms"] or "").split(",") if p]}


@app.route("/admin", methods=["GET", "POST"])
def admin():
    err = ""
    if request.method == "POST":
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr
        now = time.time()
        FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
        c = conn()
        u = c.execute("select * from users where username=? and active=1", (request.form.get("user", "").strip(),)).fetchone()
        c.close()
        if len(FAILS[ip]) >= 8:
            err = "<p style='color:#b00'>محاولات كثيرة، انتظر 10 دقائق</p>"
        elif u and check_password_hash(u["pw"], request.form.get("key", "")):
            session["uid"] = u["id"]
            audit("تسجيل دخول", "تم تسجيل الدخول بنجاح", user=u)
            return redirect("/admin")
        else:
            audit("محاولة دخول فاشلة", "اسم المستخدم: " + request.form.get("user", "")[:80])
            FAILS[ip].append(now)
            err = "<p style='color:#b00'>اسم المستخدم أو كلمة السر غلط</p>"
    u = me()
    if not u:
        return Response(f"""<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;max-width:320px;margin:60px auto">
<h3>دخول الإدارة</h3>{err}<form method="post"><input name="user" placeholder="اسم المستخدم" style="width:100%;padding:10px;margin-bottom:6px" autofocus>
<input type="password" name="key" placeholder="كلمة السر" style="width:100%;padding:10px">
<button style="margin-top:8px;padding:10px;width:100%">دخول</button></form>""", mimetype="text/html")
    info = {"name": u["username"], "owner": u["role"] == "owner", "perms": uview(u)["perms"]}
    return Response(ADMIN.replace("__COLOR__", COLOR).replace("__A1__", A1).replace("__A2__", A2).replace("__LOW__", str(LOW)).replace("__ME__", json.dumps(info)),
                    mimetype="text/html")


@app.get("/admin/logout")
def logout():
    audit("تسجيل خروج", "تم تسجيل الخروج")
    session.clear()
    return redirect("/admin")


@app.get("/admin/api/users")
def a_users():
    owner()
    c = conn()
    r = [uview(u) for u in c.execute("select * from users order by id")]
    c.close()
    return jsonify(r)


@app.post("/admin/api/users")
def a_user_save():
    owner()
    j = request.get_json(force=True) or {}
    perms = ",".join(p for p in j.get("perms", []) if p in PERMS)
    pw = str(j.get("password") or "")
    c = conn()
    try:
        if j.get("id"):
            u = c.execute("select * from users where id=?", (j["id"],)).fetchone()
            if not u:
                return jsonify(error="المستخدم غير موجود"), 404
            if pw and len(pw) < 6:
                return jsonify(error="كلمة السر 6 أحرف على الأقل"), 400
            if u["role"] != "owner":
                c.execute("update users set perms=?, active=? where id=?",
                          (perms, 1 if str(j.get("active", 1)) in ("1", "True", "true") else 0, u["id"]))
            if pw:
                c.execute("update users set pw=? where id=?", (generate_password_hash(pw), u["id"]))
        else:
            name = str(j.get("username", "")).strip()
            if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", name) or len(pw) < 6:
                return jsonify(error="اسم المستخدم إنكليزي (3-20 حرف) وكلمة السر 6 أحرف على الأقل"), 400
            c.execute("insert into users(username,pw,perms) values(?,?,?)", (name, generate_password_hash(pw), perms))
        c.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="اسم المستخدم مستخدم من قبل"), 400
    finally:
        c.close()
    audit("حفظ مستخدم", "إضافة أو تعديل مستخدم: " + str(j.get("username") or j.get("id") or ""))
    return jsonify(ok=1)


@app.post("/admin/api/users/<int:uid>/delete")
def a_user_del(uid):
    owner()
    c = conn()
    c.execute("delete from users where id=? and role!='owner'", (uid,))
    c.commit()
    c.close()
    audit("حذف مستخدم", f"معرّف المستخدم: {uid}")
    return jsonify(ok=1)


@app.post("/admin/api/password")
def a_password():
    u = me()
    if not u:
        abort(403)
    j = request.get_json(force=True) or {}
    new = str(j.get("new", ""))
    if not check_password_hash(u["pw"], str(j.get("old", ""))) or len(new) < 6:
        return jsonify(error="كلمة السر الحالية غلط أو الجديدة قصيرة"), 400
    c = conn()
    c.execute("update users set pw=? where id=?", (generate_password_hash(new), u["id"]))
    c.commit()
    c.close()
    audit("تغيير كلمة المرور", "تم تغيير كلمة المرور للمستخدم الحالي")
    return jsonify(ok=1)


@app.get("/admin/api/products")
def a_products():
    need('products', 'stock')
    return jsonify(prods(False))


@app.get("/admin/api/orders")
def a_orders():
    need('orders')
    c = conn()
    r = [dict(x) for x in c.execute("select * from orders order by id desc limit 200")]
    c.close()
    return jsonify(r)


@app.post("/admin/api/products")
def a_save():
    need('products')
    f = request.form
    try:
        name, price = f["name"].strip()[:150], float(f["price"])
        purchase_price = float(f.get("purchase_price", "0") or 0)
        assert name and price >= 0 and purchase_price >= 0
    except (KeyError, ValueError, AssertionError):
        return jsonify(error="الاسم أو السعر غير صحيح"), 400
    img = save_img(request.files.get("image"))
    try:
        stock = int(f["stock"]) if f.get("stock", "").strip() != "" else None
    except ValueError:
        return jsonify(error="المخزون لازم يكون رقم"), 400
    vals = [name, price, f.get("desc", "")[:500], f.get("category", "").strip()[:50], 1 if f.get("active", "1") == "1" else 0, f.get("badge", "").strip()[:20], stock, purchase_price]
    c = conn()
    if f.get("id"):
        c.execute("update products set name=?,price=?,descr=?,category=?,active=?,badge=?,stock=?,purchase_price=? where id=?", vals + [f["id"]])
        if img:
            c.execute("update products set image=? where id=?", (img, f["id"]))
    else:
        c.execute("insert into products(name,price,descr,category,active,badge,stock,purchase_price,image) values(?,?,?,?,?,?,?,?,?)", vals + [img or ""])
    c.commit()
    c.close()
    audit("حفظ منتج", f"المنتج: {name}؛ سعر الشراء: {purchase_price:g}؛ سعر البيع: {price:g}")
    return jsonify(ok=1)


@app.post("/admin/api/products/<int:pid>/delete")
def a_delete(pid):
    need('products')
    c = conn()
    c.execute("delete from products where id=?", (pid,))
    c.commit()
    c.close()
    audit("حذف منتج", f"معرّف المنتج: {pid}")
    return jsonify(ok=1)


@app.post("/admin/api/orders/<int:oid>/status")
def a_status(oid):
    need('orders')
    s = (request.get_json(force=True) or {}).get("status")
    if s not in ("new", "shipping", "done", "cancel"):
        return jsonify(error="حالة غير صحيحة"), 400
    c = conn()
    row = c.execute("select status, items_json from orders where id=?", (oid,)).fetchone()
    if row and row["items_json"]:
        old = row["status"] or "new"
        sign = 1 if (s == "cancel" and old != "cancel") else -1 if (old == "cancel" and s != "cancel") else 0
        if sign:
            for pid, q in json.loads(row["items_json"]):
                c.execute("update products set stock=max(0,stock+?) where id=? and stock is not null", (sign * q, pid))
    c.execute("update orders set status=? where id=?", (s, oid))
    c.commit()
    c.close()
    audit("تغيير حالة طلب", f"الطلب #{oid} إلى الحالة {s}")
    return jsonify(ok=1)


@app.get("/admin/api/banners")
def a_banners():
    need('banners')
    return jsonify(banners())


@app.post("/admin/api/banners")
def a_banner_save():
    need('banners')
    f = request.form
    img = save_img(request.files.get("image"))
    if not (img or f.get("title", "").strip()):
        return jsonify(error="ارفع صورة أو اكتب عنواناً"), 400
    c = conn()
    c.execute("insert into banners(title,subtitle,link,image) values(?,?,?,?)",
              (f.get("title", "")[:100], f.get("subtitle", "")[:200], f.get("link", "")[:300], img or ""))
    c.commit()
    c.close()
    audit("إضافة بنر", f"العنوان: {f.get('title', '')[:100]}")
    return jsonify(ok=1)


@app.post("/admin/api/banners/<int:bid>/delete")
def a_banner_del(bid):
    need('banners')
    c = conn()
    c.execute("delete from banners where id=?", (bid,))
    c.commit()
    c.close()
    audit("حذف بنر", f"معرّف البنر: {bid}")
    return jsonify(ok=1)


@app.post("/admin/api/products/<int:pid>/stock")
def a_stock(pid):
    need('stock')
    j = request.get_json(force=True) or {}
    c = conn()
    try:
        if "set" in j:
            v = None if j["set"] in (None, "") else max(0, int(j["set"]))
            c.execute("update products set stock=? where id=?", (v, pid))
        else:
            c.execute("update products set stock=max(0,coalesce(stock,0)+?) where id=?", (int(j["delta"]), pid))
        c.commit()
    except (ValueError, KeyError, TypeError):
        return jsonify(error="قيمة غير صحيحة"), 400
    finally:
        c.close()
    audit("تعديل المخزون", f"المنتج #{pid}: {json.dumps(j, ensure_ascii=False)}")
    return jsonify(ok=1)


@app.post("/admin/api/orders/<int:oid>/delete")
def a_order_del(oid):
    need('orders')
    c = conn()
    row = c.execute("select status, items_json from orders where id=?", (oid,)).fetchone()
    if row and row["items_json"] and (row["status"] or "new") in ("new", "shipping"):
        for pid, q in json.loads(row["items_json"]):
            c.execute("update products set stock=stock+? where id=? and stock is not null", (q, pid))
    c.execute("delete from orders where id=?", (oid,))
    c.commit()
    c.close()
    audit("حذف طلب", f"معرّف الطلب: {oid}")
    return jsonify(ok=1)


@app.get("/admin/api/reports")
def a_reports():
    owner()
    c = conn()
    start_date = (request.args.get("from") or "").strip()
    end_date = (request.args.get("to") or "").strip()
    status_filter = (request.args.get("status") or "").strip()
    sql = "select id,created,status,total,items_snapshot,items_subtotal,delivery_fee,items_json,items from orders where 1=1"
    args = []
    if start_date:
        sql += " and substr(created,1,10) >= ?"; args.append(start_date)
    if end_date:
        sql += " and substr(created,1,10) <= ?"; args.append(end_date)
    if status_filter in ("new", "shipping", "done", "cancel"):
        sql += " and coalesce(status,'new') = ?"; args.append(status_filter)
    sql += " order by id desc"
    orders = [dict(r) for r in c.execute(sql, args)]
    products = [dict(r) for r in c.execute("select id,name,price,purchase_price,stock from products order by name")]
    c.close()
    by_status = {}
    product_totals = {}
    totals = {"orders": len(orders), "revenue": 0.0, "cost": 0.0, "profit": 0.0, "delivery": 0.0, "completed_revenue": 0.0, "completed_cost": 0.0, "completed_profit": 0.0, "legacy_orders": 0}
    labels = {"new":"جديد", "shipping":"قيد التوصيل", "done":"مكتمل", "cancel":"ملغي"}
    for o in orders:
        status = o.get("status") or "new"
        bucket = by_status.setdefault(status, {"status": status, "label": labels.get(status,status), "count": 0, "revenue": 0.0, "cost": 0.0, "profit": 0.0, "delivery": 0.0})
        bucket["count"] += 1
        try:
            snap = json.loads(o.get("items_snapshot") or "[]")
        except Exception:
            snap = []
        if not snap and o.get("items_json"):
            try:
                olditems = json.loads(o["items_json"])
                for pid, qty in olditems:
                    prod = next((p for p in products if p["id"] == pid), None)
                    if prod:
                        snap.append({"id":pid,"name":prod["name"],"qty":qty,"sale_price":prod["price"],"purchase_price":prod.get("purchase_price") or 0,"line_total":prod["price"]*qty,"estimated":True})
                if snap: totals["legacy_orders"] += 1
            except Exception:
                pass
        revenue = float(o.get("items_subtotal") or sum(float(i.get("sale_price",0))*int(i.get("qty",0)) for i in snap))
        cost = sum(float(i.get("purchase_price",0))*int(i.get("qty",0)) for i in snap)
        profit = revenue - cost
        delivery = float(o.get("delivery_fee") or max(0, float(o.get("total") or 0)-revenue))
        bucket["revenue"] += revenue; bucket["cost"] += cost; bucket["profit"] += profit; bucket["delivery"] += delivery
        totals["revenue"] += revenue; totals["cost"] += cost; totals["profit"] += profit; totals["delivery"] += delivery
        if status == "done":
            totals["completed_revenue"] += revenue; totals["completed_cost"] += cost; totals["completed_profit"] += profit
        for i in snap:
            pid = i.get("id")
            name = i.get("name") or (next((p["name"] for p in products if p["id"] == pid), "منتج محذوف"))
            q = int(i.get("qty",0)); sr = float(i.get("sale_price",0)); pr = float(i.get("purchase_price",0))
            t = product_totals.setdefault(str(pid), {"id":pid,"name":name,"qty":0,"revenue":0.0,"cost":0.0,"profit":0.0})
            t["qty"] += q; t["revenue"] += sr*q; t["cost"] += pr*q; t["profit"] += (sr-pr)*q
    return jsonify(currency=CUR, totals=totals, statuses=list(by_status.values()), products=sorted(product_totals.values(),key=lambda x:x["revenue"],reverse=True), database_path=DB, uploads_path=UP)


@app.get("/admin/api/activity")
def a_activity():
    owner()
    c = conn()
    rows = [dict(r) for r in c.execute("select id,created,username,action,details,ip,method,path from activity_logs order by id desc limit 500")]
    c.close()
    return jsonify(rows)


@app.get("/admin/api/wa")
def a_wa():
    need('orders')
    return jsonify(configured=bool(WA_TOKEN and WA_PHONE_ID and WA), **WA_STATE)


@app.post("/admin/api/logo")
def a_logo():
    need('logo')
    f = request.files.get("image")
    if not f or not f.filename or f.filename.rsplit(".", 1)[-1].lower() not in EXT:
        return jsonify(error="ارفع صورة png أو jpg أو webp"), 400
    for old in glob.glob(os.path.join(UP, "logo.*")):
        os.remove(old)
    save_img(f, "logo")
    audit("تغيير الشعار", "تم رفع شعار جديد")
    return jsonify(ok=1)


# ---------------- التطبيق (PWA) ----------------
@app.get("/manifest.json")
def manifest():
    lg = logo().split("?")[0]
    icon = ({"src": lg, "sizes": "512x512", "type": "image/" + lg.rsplit(".", 1)[-1].replace("jpg", "jpeg")}
            if lg else {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"})
    return jsonify(name=NAME, short_name=NAME, start_url="/", display="standalone", dir="rtl", lang="ar",
                   background_color="#0a0a10", theme_color="#0a0a10", icons=[icon])


@app.get("/sw.js")
def sw():
    return Response("self.addEventListener('install',e=>self.skipWaiting());"
                    "self.addEventListener('fetch',()=>{});", mimetype="application/javascript")


@app.get("/icon.svg")
def icon():
    return Response(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" '
                    f'rx="22" fill="{COLOR}"/><text x="50" y="68" font-size="56" text-anchor="middle">🛒</text></svg>',
                    mimetype="image/svg+xml")


CSS = """:root{--c:__COLOR__;--t:color-mix(in srgb,var(--c) 10%,#fff);--b:#e6e9e8;--tx:#1d2523}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;font-family:Tajawal,Tahoma,"Segoe UI",system-ui,sans-serif;background:#f6f8f7;color:var(--tx);line-height:1.5}
button{font:inherit;cursor:pointer;border:0;border-radius:10px;padding:10px 14px;background:var(--c);color:#fff;font-weight:600}
button:disabled{opacity:.6}button.g{background:#eef1f0;color:var(--tx)}button.d{background:#c0392b}
input,textarea,select{width:100%;padding:11px 12px;border:1px solid var(--b);border-radius:10px;font:inherit;background:#fff;margin:5px 0}
input:focus,textarea:focus,select:focus{outline:2px solid var(--c);border-color:transparent}
.err{color:#c0392b;font-size:14px;margin:4px 0}.r{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:9px 0;border-bottom:1px solid var(--b)}
header{background:#fff;border-bottom:1px solid var(--b);position:sticky;top:0;z-index:20}
.in{max-width:1000px;margin:auto;padding:10px 14px;display:flex;align-items:center;justify-content:space-between}
main{max-width:1000px;margin:auto;padding:14px}
@keyframes up{from{opacity:0;transform:translateY(14px)}}@keyframes fl{50%{transform:translateY(24px) scale(1.1)}}
.gr{background:linear-gradient(135deg,var(--c),color-mix(in srgb,var(--c) 55%,#000))}
.gr::after,.gr::before{content:"";position:absolute;border-radius:50%;background:#ffffff22;animation:fl 7s ease-in-out infinite}
.gr::after{width:220px;height:220px;top:-70px;left:-50px}.gr::before{width:140px;height:140px;bottom:-50px;right:-30px;animation-delay:-3s}"""

PAGE = """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>المتجر</title>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet"><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&display=swap" rel="stylesheet"><link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#0a0a10">
<style>__CSS__
#brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700}
#brand img{height:40px;width:40px;object-fit:cover;border-radius:10px}
#cartbtn{position:relative;background:var(--t);color:var(--c);font-size:20px;padding:8px 14px}
#cn{position:absolute;top:-6px;left:-6px;background:var(--c);color:#fff;border-radius:12px;font-size:12px;min-width:20px;padding:1px 5px;text-align:center}
.hero{background:linear-gradient(135deg,var(--c),color-mix(in srgb,var(--c) 55%,#000));color:#fff;padding:30px 14px;text-align:center}
.hero h1{margin:0 0 6px;font-size:26px}.hero p{margin:0;opacity:.92}
#cats{display:flex;gap:8px;overflow-x:auto;padding:4px 0 12px}
.chip{background:#fff;color:var(--tx);border:1px solid var(--b);border-radius:20px;white-space:nowrap;padding:7px 14px;font-weight:500}
.chip.on{background:var(--c);color:#fff;border-color:var(--c)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.card{background:#fff;border:1px solid var(--b);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
.im,.pimg{aspect-ratio:1;background:var(--t);display:flex;align-items:center;justify-content:center;font-size:44px;cursor:pointer;overflow:hidden}
.im img,.pimg img{width:100%;height:100%;object-fit:cover}.pimg{border-radius:14px;margin-bottom:10px;max-height:280px;aspect-ratio:auto;height:240px}
.bd{padding:10px;display:flex;flex-direction:column;gap:6px;flex:1;justify-content:space-between}
.nm{font-weight:600;font-size:15px}.pc{color:var(--c);font-weight:800}
.qty{display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--t);border-radius:10px;padding:3px}
.qty button{padding:4px 13px;font-size:18px}
#ov{position:fixed;inset:0;background:#0007;display:none;z-index:30}#ov.on{display:block}
.sheet{position:fixed;z-index:40;background:#fff;left:0;right:0;bottom:0;max-height:92vh;overflow:auto;border-radius:20px 20px 0 0;padding:18px;transform:translateY(105%);transition:.25s;max-width:560px;margin:auto}
.sheet.on{transform:none}.x{float:left;padding:5px 12px}.tot{font-size:18px;font-weight:800}
.empty,.center{text-align:center;padding:30px 0}.big{font-size:56px}
.wa{display:block;background:#25d366;color:#fff;text-decoration:none;padding:14px;border-radius:12px;font-weight:700;margin-top:14px}
#toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%);background:#222;color:#fff;padding:10px 18px;border-radius:20px;opacity:0;transition:.3s;z-index:50;pointer-events:none}#toast.on{opacity:1}
footer{text-align:center;color:#78827f;padding:24px 24px 100px;font-size:14px}
#cb{position:fixed;bottom:14px;left:0;right:0;margin:auto;width:min(92%,440px);background:var(--c);color:#fff;padding:14px;border-radius:14px;text-align:center;font-weight:700;box-shadow:0 6px 20px #0004;z-index:24;cursor:pointer;animation:up .3s both}#cb[hidden]{display:none}
.ds{color:#78827f;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;font-size:13px}
#slider{position:relative;height:210px;overflow:hidden;color:#fff;background:var(--c)}
.slide{position:absolute;inset:0;opacity:0;transition:opacity .8s;background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;text-align:center;cursor:pointer}
.slide.on{opacity:1}.slide.pic.on{animation:kb 6s ease-out forwards}@keyframes kb{from{transform:scale(1)}to{transform:scale(1.07)}}
.slide.pic::before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,#0000,#0008)}
.tx{position:relative;z-index:1;padding:0 18px}.tx h1{margin:0 0 6px;font-size:27px;text-shadow:0 2px 8px #0005}.tx p{margin:0;font-size:16px}
.slide.on h1{animation:up .8s both}.slide.on p{animation:up .8s .15s both}
#dots{position:absolute;bottom:10px;left:0;right:0;display:flex;justify-content:center;gap:6px;z-index:2}
#dots i{width:8px;height:8px;border-radius:6px;background:#fff6;cursor:pointer;transition:.3s}#dots i.on{background:#fff;width:24px}
.trust{max-width:1000px;margin:14px auto 0;padding:0 14px;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.trust div{background:#fff;border:1px solid var(--b);border-radius:14px;padding:12px 6px;text-align:center;font-size:13px;font-weight:600;transition:.2s}
.trust div:hover{transform:translateY(-3px);box-shadow:0 6px 16px #0001}.trust i{display:flex;width:44px;height:44px;margin:0 auto 6px;border-radius:50%;background:var(--t);align-items:center;justify-content:center;font-size:22px;font-style:normal}
.card{transition:.2s;animation:up .5s both}.card:hover{transform:translateY(-4px);box-shadow:0 10px 24px #0001}
.im{position:relative}.im img{transition:.4s}.card:hover .im img{transform:scale(1.07)}
.badge{position:absolute;top:8px;right:8px;background:#e74c3c;color:#fff;font-size:12px;font-weight:700;padding:2px 10px;border-radius:12px;z-index:1}
.sk{height:230px;border-radius:14px;background:linear-gradient(90deg,#eceff0 25%,#f7f8f8 50%,#eceff0 75%);background-size:200% 100%;animation:sh 1.2s infinite}@keyframes sh{to{background-position:-200% 0}}
#wab{position:fixed;bottom:84px;left:16px;width:54px;height:54px;border-radius:50%;background:#25d366;color:#fff;display:flex;align-items:center;justify-content:center;font-size:26px;text-decoration:none;z-index:25;box-shadow:0 4px 14px #0004;animation:pl 2s infinite}
.lw{color:#e67e22;font-weight:700}
#wab[hidden]{display:none}@keyframes pl{0%{box-shadow:0 0 0 0 #25d36688}100%{box-shadow:0 0 0 18px #25d36600}}
:root{--c:__A1__;--v:__A2__;--bg:#0a0a10;--bg2:#10101c;--card:#15152b;--t:#1b1b36;--b:#2a2a4a;--tx:#eaeaf5;--mut:#9a9ab5}
html{scroll-behavior:smooth}#shop,#why{scroll-margin-top:70px}
body{background:var(--bg);color:var(--tx)}
button{color:#04141a}button.g{background:#232345;color:var(--tx)}button.d{background:#c0392b;color:#fff}
input,textarea,select{background:#0e0e1c;color:var(--tx);border-color:var(--b)}input::placeholder,textarea::placeholder{color:#6d6d8c}
header{background:#0a0a10ee;border-bottom:1px solid #1d1d3a;backdrop-filter:blur(8px)}
.hr{display:flex;gap:10px;align-items:center}.hb{background:transparent;color:var(--tx);font-size:24px;padding:3px 11px;border:1px solid var(--b)}
#cartbtn{background:#15152b;color:var(--c);border:1px solid #3a2a6a}#cn{background:var(--c);color:#04141a}
#brand{font-family:Orbitron,Tajawal,sans-serif;letter-spacing:1px;color:#fff}.lg b{color:var(--c);text-shadow:0 0 12px var(--c);font-size:1.3em}
#slider{height:340px;background:var(--bg);isolation:isolate}.gr{background:radial-gradient(circle at 70% 20%,#2b1b63 0,#0a0a10 65%)}
#slides{position:absolute;inset:0;touch-action:pan-y}.slide{user-select:none;-webkit-tap-highlight-color:transparent}.slide.pic{background-position:center;background-size:cover}
.slide-arrow{position:absolute;top:50%;transform:translateY(-50%);z-index:5;width:42px;height:42px;border-radius:50%;border:1px solid #ffffff70;background:#080817b8;color:#fff;font-size:28px;line-height:1;display:flex;align-items:center;justify-content:center;box-shadow:0 3px 14px #0005;cursor:pointer;padding:0}.slide-arrow.prev{right:12px}.slide-arrow.next{left:12px}.slide-arrow:active{transform:translateY(-50%) scale(.94)}
@media(max-width:700px){#slider{height:245px;min-height:220px}.tx h1{font-size:24px}.tx p{font-size:15px}.pill{bottom:36px;padding:10px 22px}.slide-arrow{width:38px;height:38px;font-size:25px}.slide-arrow.prev{right:8px}.slide-arrow.next{left:8px}#dots{bottom:8px}}
.gr::after{background:#00e5ff1f}.gr::before{background:#a855f733}.slide.pic::before{background:linear-gradient(0deg,#0a0a10cc,#0a0a1066)}
.tx h1{color:#fff;font-size:30px}.gt{background:linear-gradient(90deg,var(--v),var(--c));-webkit-background-clip:text;background-clip:text;color:transparent}
.tx p{color:var(--c);font-size:18px}
.pill{position:absolute;bottom:40px;left:0;right:0;margin:auto;width:max-content;z-index:3;padding:13px 34px;border:1.5px solid var(--v);border-radius:40px;color:var(--c);text-decoration:none;font-weight:700;background:#a855f71a;box-shadow:0 0 18px #a855f733}
.stats2{display:flex;justify-content:space-around;padding:26px 14px;background:var(--bg2);border-bottom:1px solid #1d1d3a;text-align:center}
.stats2 b{display:block;font-family:Orbitron,sans-serif;font-size:28px;background:linear-gradient(90deg,var(--c),var(--v));-webkit-background-clip:text;background-clip:text;color:transparent}.stats2 small{color:var(--mut)}
.sh{text-align:center;margin:30px 0 18px}.sh small{display:block;color:var(--c);letter-spacing:1px}
.sh h2{margin:6px 0 0;font-size:30px;background:linear-gradient(90deg,var(--v),var(--c));-webkit-background-clip:text;background-clip:text;color:transparent}
.chip{background:var(--card);color:var(--tx);border-color:var(--b)}.chip.on{background:var(--c);color:#04141a;border-color:var(--c)}
.card{background:var(--card);border-color:var(--b);border-radius:16px}.card:hover{border-color:var(--v);box-shadow:0 0 22px #a855f722}
.pc{color:var(--c);font-family:Orbitron,Tajawal,sans-serif}.ds{color:var(--mut)}
.tg2{align-self:flex-start;font-size:12px;color:#c08cff;border:1px solid #4b2f8a;background:#a855f714;border-radius:20px;padding:2px 10px}
.qty{background:#0e0e1c}.qty b{color:var(--tx)}.sheet{background:#12122a;color:var(--tx);border-top:1px solid var(--b)}
.menu a{display:block;padding:14px 4px;color:var(--tx);text-decoration:none;border-bottom:1px solid var(--b);font-size:18px}
.svc{max-width:1000px;margin:34px auto 0;padding:10px 14px;border-top:1px solid;border-image:linear-gradient(90deg,transparent,var(--c),transparent) 1}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.sc{background:var(--card);border:1px solid var(--b);border-radius:16px;padding:20px;transition:.2s}.sc:hover{border-color:var(--v);transform:translateY(-3px)}
.sc i{display:flex;width:56px;height:56px;border-radius:14px;align-items:center;justify-content:center;color:var(--c);background:#00e5ff12;box-shadow:0 0 18px #00e5ff22}
.sc svg{width:30px;height:30px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.sc h3{margin:14px 0 6px}.sc p{color:var(--mut);margin:0 0 12px}.tg{display:flex;gap:8px;flex-wrap:wrap}
.tg span{font-size:13px;color:#c08cff;border:1px solid #4b2f8a;background:#a855f714;border-radius:20px;padding:4px 14px}
.sk{background:linear-gradient(90deg,#15152b 25%,#1d1d3a 50%,#15152b 75%);background-size:200% 100%}
footer{color:var(--mut)}#cb{background:linear-gradient(90deg,var(--c),#7aa8ff);color:#04141a}
#toast{background:#1d1d3a;color:var(--tx);border:1px solid var(--v)}.empty{color:var(--mut)}</style>
<header><div class="in"><div id="brand"></div><div class="hr"><button id="cartbtn" onclick="sheet('cart')">🛒<b id="cn">0</b></button><button class="hb" onclick="sheet('menu')" aria-label="menu">☰</button></div></div></header>
<div id="slider"><div id="slides"></div><button class="slide-arrow prev" id="slidePrev" type="button" aria-label="البنر السابق">‹</button><button class="slide-arrow next" id="slideNext" type="button" aria-label="البنر التالي">›</button><a class="pill" id="cta" href="#shop">🛍️ تسوّق الآن</a><div id="dots"></div></div>
<div class="stats2" id="stt"></div>
<main id="shop"><div class="sh"><small>// تسوّق</small><h2>منتجاتنا</h2></div><input id="q" placeholder="🔍 ابحث عن منتج..."><div id="cats"></div><div class="grid" id="pr"><div class="sk"></div><div class="sk"></div><div class="sk"></div><div class="sk"></div></div></main>
<section class="svc" id="why"><div class="sh"><small>// لماذا نحن</small><h2>خدماتنا</h2></div><div class="sg">
<div class="sc"><i><svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="3"/></svg></i><h3>الدفع عند الاستلام</h3><p>اطلب الآن وادفع لما يوصلك طلبك، بدون أي دفع إلكتروني.</p><div class="tg"><span>دفع نقدي</span><span>بدون بطاقات</span></div></div>
<div class="sc"><i><svg viewBox="0 0 24 24"><path d="M1 6h13v10H1zM14 10h4l3 3v3h-7z"/><circle cx="6" cy="18" r="2"/><circle cx="17" cy="18" r="2"/></svg></i><h3>التوصيل إلى بابك</h3><p>اكتب معلوماتك وعنوانك واحجز طلبك بخطوات بسيطة.</p><div class="tg"><span>توصيل منزلي</span><span>حجز سهل</span></div></div>
<div class="sc"><i><svg viewBox="0 0 24 24"><path d="M21 12a8 8 0 0 1-11.5 7.2L4 20l1-4.5A8 8 0 1 1 21 12z"/></svg></i><h3>تواصل عبر واتساب</h3><p>أي استفسار عن منتج أو طلب، راسلنا مباشرة.</p><div class="tg"><span>استفسارات</span><span>متابعة الطلب</span></div></div>
</div></section>
<footer id="ft"></footer>
<div id="ov" onclick="closeAll()"></div><div class="sheet" id="sh"></div><div id="cb" hidden onclick="sheet('cart')"></div><div id="toast"></div><a id="wab" hidden target="_blank">💬</a>
<script>
const $=s=>document.getElementById(s),f=n=>(+n).toLocaleString('en'),
E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let P=[],FEE=0,CUR='',cat='',F={},C={},V=null,D=null;
try{C=JSON.parse(localStorage.getItem('cart')||'{}')}catch(e){}
const save=()=>{try{localStorage.setItem('cart',JSON.stringify(C))}catch(e){}};
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js');
function toast(t){const e=$('toast');e.textContent=t;e.classList.add('on');setTimeout(()=>e.classList.remove('on'),1400)}
async function init(){const r=await (await fetch('/api/products')).json();P=r.products;FEE=r.fee;CUR=r.currency;
document.title=r.name;$('brand').innerHTML=(r.logo?`<img src="${r.logo}" alt="">`:'')+`<span class="lg"><b>${E(r.name.charAt(0))}</b>${E(r.name.slice(1))}</span>`;
LW=r.low;WAN=r.whatsapp||'';slider(r.banners||[],r);if(r.whatsapp){const a=$('wab');a.href='https://wa.me/'+r.whatsapp;a.hidden=false}$('ft').textContent='© '+r.name+' • الدفع عند الاستلام';
const cs=[...new Set(P.map(p=>p.category).filter(Boolean))];
$('stt').innerHTML=[[P.length,'منتج'],[cs.length,'تصنيف'],[P.filter(p=>p.stock==null||p.stock>0).length,'متوفر الآن']].map(x=>`<div><b>${x[0]}</b><small>${x[1]}</small></div>`).join('');
$('cats').innerHTML=cs.length?['الكل',...cs].map((c,i)=>`<button class="chip${i?'':' on'}" data-c="${i?E(c):''}">${E(c)}</button>`).join(''):'';
$('cats').onclick=e=>{if(e.target.dataset.c===undefined)return;cat=e.target.dataset.c;[...$('cats').children].forEach(b=>b.classList.toggle('on',b===e.target));show()};
$('q').oninput=show;show();badge()}
let SI=0,TM;
function slider(bs,r){const L=bs.length?bs:[{title:r.name,subtitle:r.tagline,image:'',link:''}];SI=0;
$('slides').innerHTML=L.map((b,i)=>`<div class="slide${b.image?' pic':' gr'}${i?'':' on'}" data-href="${E(b.link)}" style="${b.image?`background-image:url('/uploads/${E(b.image)}')`:''}"><div class="tx">${b.title?`<h1>${gt(b.title)}</h1>`:''}${b.subtitle?`<p>${E(b.subtitle)}</p>`:''}</div></div>`).join('');
$('dots').innerHTML=L.length>1?L.map((_,i)=>`<i class="${i?'':'on'}" data-i="${i}"></i>`).join(''):'';
const go=n=>{const s=$('slides').children,d=$('dots').children;if(!s.length)return;s[SI].classList.remove('on');d[SI]&&d[SI].classList.remove('on');SI=(n+L.length)%L.length;s[SI].classList.add('on');d[SI]&&d[SI].classList.add('on')};
const rs=()=>{clearInterval(TM);if(L.length>1)TM=setInterval(()=>go(SI+1),4500)};
$('dots').onclick=e=>{if(e.target.dataset.i!==undefined){go(+e.target.dataset.i);rs()}};
$('slidePrev').hidden=$('slideNext').hidden=L.length<2;
$('slidePrev').onclick=e=>{e.preventDefault();e.stopPropagation();go(SI-1);rs()};$('slideNext').onclick=e=>{e.preventDefault();e.stopPropagation();go(SI+1);rs()};
$('slides').onclick=e=>{const el=e.target.closest('.slide');if(!el)return;const h=el.dataset.href||'';if(h.startsWith('http')||h.startsWith('/'))location.href=h};
let touchX=0,touchY=0;$('slider').ontouchstart=e=>{touchX=e.changedTouches[0].clientX;touchY=e.changedTouches[0].clientY};$('slider').ontouchend=e=>{if(L.length<2)return;const dx=e.changedTouches[0].clientX-touchX,dy=e.changedTouches[0].clientY-touchY;if(Math.abs(dx)>45&&Math.abs(dx)>Math.abs(dy)){go(dx<0?SI+1:SI-1);rs()}};rs()}
let LW=5,WAN='';
const gt=t=>{const w=String(t).split(' ');return w.length>1?E(w.slice(0,-1).join(' '))+' <span class="gt">'+E(w[w.length-1])+'</span>':'<span class="gt">'+E(t)+'</span>'};
function menuV(){return `<h3>${E(document.title)}</h3><div class="menu"><a href="#top" onclick="closeAll()">🏠 الرئيسية</a><a href="#shop" onclick="closeAll()">🛍️ منتجاتنا</a><a href="#why" onclick="closeAll()">⭐ خدماتنا</a><a href="#" onclick="sheet('cart');return false">🛒 السلة</a>${WAN?`<a href="https://wa.me/${E(WAN)}" target="_blank">💬 تواصل معنا</a>`:''}</div>`}
const out=p=>p.stock!=null&&p.stock<=0;
const low=p=>p.stock!=null&&p.stock>0&&p.stock<=LW?`<small class="lw">باقي ${p.stock} فقط!</small>`:'';
const ctl=p=>out(p)?'<button disabled>نفدت الكمية</button>':C[p.id]?`<div class="qty"><button onclick="add(${p.id},-1)">−</button><b>${C[p.id]}</b><button onclick="add(${p.id},1)">+</button></div>`:`<button onclick="add(${p.id},1)">أضف للسلة</button>`;
function show(){const q=$('q').value.trim().toLowerCase();
const L=P.filter(p=>(!cat||p.category===cat)&&(!q||(p.name+' '+p.desc).toLowerCase().includes(q)));
$('pr').innerHTML=L.map(p=>`<div class="card"><div class="im" onclick="sheet(${p.id})">${p.badge?`<span class="badge">${E(p.badge)}</span>`:''}${p.image?`<img src="/uploads/${E(p.image)}" alt="" loading="lazy">`:'📦'}</div>
<div class="bd"><span class="nm">${E(p.name)}</span>${p.desc?`<small class="ds">${E(p.desc)}</small>`:''}${p.category?`<span class="tg2">${E(p.category)}</span>`:''}<span class="pc">${f(p.price)} ${E(CUR)}</span>${low(p)}${ctl(p)}</div></div>`).join('')||'<p>لا توجد منتجات مطابقة</p>'}
function badge(){let n=0,s=0;Object.keys(C).forEach(i=>{const p=P.find(x=>x.id==i);if(p){n+=C[i];s+=p.price*C[i]}});
$('cn').textContent=n;const b=$('cb');b.hidden=!n||V=='cart';b.textContent=`🛒 عرض السلة (${n}) · ${f(s)} ${CUR}`}
function add(id,d){const p=P.find(x=>x.id==id);if(d>0&&p&&p.stock!=null&&(C[id]||0)>=p.stock){toast('وصلت للكمية المتوفرة');return}C[id]=(C[id]||0)+d;if(C[id]<=0)delete C[id];save();badge();show();paint();if(d>0)toast('تمت الإضافة ✓')}
function sheet(v,d){V=v;if(d)D=d;paint();badge();$('sh').classList.add('on');$('ov').classList.add('on')}
function closeAll(){V=null;badge();$('sh').classList.remove('on');$('ov').classList.remove('on')}
function paint(){if(!V)return;$('sh').innerHTML='<button class="g x" onclick="closeAll()">✕ إغلاق</button>'+(V=='cart'?cartV():V=='done'?doneV():V=='menu'?menuV():prodV(V))}
function prodV(id){const p=P.find(x=>x.id==id);if(!p)return '';
return `<div class="pimg">${p.image?`<img src="/uploads/${E(p.image)}" alt="">`:'📦'}</div><h3>${E(p.name)}</h3><div class="pc" style="font-size:20px">${f(p.price)} ${E(CUR)}</div><p>${E(p.desc)}</p>${ctl(p)}<button class="g" style="width:100%;margin-top:8px" onclick="sheet('cart')">عرض السلة</button>`}
function cartV(){const L=Object.keys(C).map(i=>P.find(p=>p.id==i)).filter(Boolean);
if(!L.length)return '<div class="empty"><div class="big">🛒</div>السلة فارغة</div>';let sub=0;
const rows=L.map(p=>{const q=C[p.id];sub+=p.price*q;return `<div class="r"><span>${E(p.name)}<br><small>${f(p.price)} ${E(CUR)}</small></span><span class="qty"><button onclick="add(${p.id},-1)">−</button><b>${q}</b><button onclick="add(${p.id},1)">+</button></span><b>${f(p.price*q)}</b></div>`}).join('');
const inp=(k,ph,t)=>`<input type="${t||'text'}" placeholder="${ph}" value="${E(F[k]||'')}" oninput="F.${k}=this.value">`;
return `<h3>سلتك</h3>${rows}<div class="r"><span>التوصيل</span><span>${f(FEE)}</span></div><div class="r tot"><span>الإجمالي</span><span>${f(sub+FEE)} ${E(CUR)}</span></div>
<h3>معلومات التوصيل</h3>${inp('name','الاسم الكامل')}${inp('phone','رقم الهاتف','tel')}${inp('city','المحافظة / المدينة')}${inp('address','العنوان بالتفصيل')}
<textarea rows="2" placeholder="ملاحظات (اختياري)" oninput="F.notes=this.value">${E(F.notes||'')}</textarea>
<p>💵 الدفع عند الاستلام</p><p class="err" id="msg"></p><button id="go" style="width:100%" onclick="send()">حجز الطلب</button>`}
function doneV(){return `<div class="center"><div class="big">✅</div><h3>تم الحجز</h3><button class="g" style="width:100%;margin-top:14px" onclick="closeAll()">حسناً</button></div>`}
async function send(){const m=$('msg'),items=Object.keys(C).filter(i=>P.find(p=>p.id==i)).map(i=>({id:i,qty:C[i]}));
const bad=(F.name||'').trim().length<3?'اكتب الاسم الكامل':(F.phone||'').replace(/[^0-9]/g,'').length<10?'رقم الهاتف غير صحيح':!(F.city||'').trim()||!(F.address||'').trim()?'اكتب المحافظة والعنوان':'';
if(bad){m.textContent=bad;return}$('go').disabled=true;
try{const r=await fetch('/api/orders',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...F,items})});
const j=await r.json();if(!r.ok)throw j.error;C={};save();badge();show();sheet('done',j)}
catch(e){m.textContent=e||'صار خطأ، حاول مرة ثانية';$('go').disabled=false}}
init();
</script></html>""".replace("__CSS__", CSS)

ADMIN = """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>الإدارة</title><link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>__CSS__
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:14px}
.stat{background:#fff;border:1px solid var(--b);border-radius:12px;padding:14px;text-align:center}.stat b{font-size:22px;display:block;color:var(--c)}
.report-head{border:1px solid #34345b;background:linear-gradient(135deg,#15152b,#10101c);box-shadow:0 8px 28px #0002}.report-head h2{margin:0 0 8px}.report-head p{color:var(--mut);margin:0 0 14px}.report-filters{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:10px;align-items:end}.report-filters label{display:flex;flex-direction:column;gap:5px;font-size:13px;color:var(--mut)}.report-filters input,.report-filters select{width:100%;min-width:0;box-sizing:border-box}.report-actions{grid-column:1/-1}.report-actions button{margin:0 5px 0 0}.report-row{display:grid;grid-template-columns:minmax(100px,1.3fr) repeat(4,minmax(75px,1fr));gap:8px;align-items:center;padding:12px 4px;border-bottom:1px solid var(--b)}.report-row:last-child{border-bottom:0}.report-row small{color:var(--mut)}.profit{color:#49d89a;font-weight:800}.loss{color:#ff7887;font-weight:800}.report-section-title{display:flex;align-items:center;justify-content:space-between;gap:8px}.report-count{color:var(--mut);font-size:12px}

.tabs{display:flex;gap:8px;margin-bottom:12px}.chip{background:#fff;color:var(--tx);border:1px solid var(--b);border-radius:20px}.chip.on{background:var(--c);color:#fff}
.box,.oc{background:#fff;border:1px solid var(--b);border-radius:12px;padding:14px;margin-bottom:12px}[hidden]{display:none!important}
.bd{padding:2px 10px;border-radius:12px;font-size:13px;background:#eee}.s-new{background:#fff3cd}.s-shipping{background:#d6e9ff}.s-done{background:#d4f5dd}.s-cancel{background:#f8d7da}
pre{margin:6px 0;font:inherit;white-space:pre-wrap;background:#f6f8f7;padding:8px;border-radius:8px}
.lk{display:inline-block;background:var(--t);color:var(--c);text-decoration:none;padding:7px 12px;border-radius:10px;margin:4px 4px 0 0;font-weight:600}
.pg{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}.pg .box{margin:0}.pg img{width:100%;height:110px;object-fit:cover;border-radius:8px}
#nb{background:#fff3cd;border:2px solid #f39c12;border-radius:12px;padding:12px;margin-bottom:12px;font-weight:700;cursor:pointer;animation:up .4s both}
#ab{position:relative;overflow:hidden;border-radius:16px;padding:28px 18px;margin-bottom:14px;color:#fff;text-align:center;min-height:96px}#am{margin:0;position:relative;z-index:1;animation:up .6s both}
.bar{height:8px;background:#eceff0;border-radius:6px;overflow:hidden;margin:6px 0}.bar i{display:block;height:100%;background:#999;transition:.4s}.bar i.s-cancel{background:#c0392b}.bar i.s-new{background:#f39c12}.bar i.s-done{background:#27ae60}
a.top{color:var(--c);text-decoration:none;font-weight:600}
/* نفس هوية وألوان واجهة المتجر */
:root{--c:__A1__;--v:__A2__;--bg:#0a0a10;--bg2:#10101c;--card:#15152b;--t:#1b1b36;--b:#2a2a4a;--tx:#eaeaf5;--mut:#9a9ab5}
html{scroll-behavior:smooth}body{background:var(--bg);color:var(--tx)}
header{background:#0a0a10ee;border-bottom:1px solid #1d1d3a;backdrop-filter:blur(8px)}
.stat,.box,.oc{background:var(--card);border-color:var(--b);color:var(--tx)}
.stat b,.pc,.a.top{color:var(--c)}
.chip{background:var(--card);color:var(--tx);border-color:var(--b)}
.chip.on{background:var(--c);color:#04141a;border-color:var(--c)}
button{background:var(--c);color:#04141a}button.g{background:#232345;color:var(--tx)}button.d{background:#c0392b;color:#fff}
input,textarea,select{background:#0e0e1c;color:var(--tx);border-color:var(--b)}
input::placeholder,textarea::placeholder{color:#6d6d8c}
input:focus,textarea:focus,select:focus{outline:2px solid var(--c);border-color:transparent}
pre{background:#0e0e1c;color:var(--tx)}
.lk{background:#1b1b36;color:var(--c);border:1px solid #2a2a4a}
#ab.gr{background:radial-gradient(circle at 70% 20%,#2b1b63 0,#0a0a10 65%)}
.gr::after{background:#00e5ff1f}.gr::before{background:#a855f733}
.bd{background:#292943;color:var(--tx)}.s-new{background:#493817;color:#ffd780}.s-shipping{background:#18334b;color:#a8d9ff}.s-done{background:#173b2b;color:#9ff0bd}.s-cancel{background:#4a2027;color:#ffb4bd}
.bar{background:#2a2a4a}.bar i.s-cancel{background:#c0392b}.bar i.s-new{background:#f39c12}.bar i.s-done{background:#27ae60}
#nb{background:#33240d;color:#ffd780;border-color:#f39c12}
#wa,small{color:var(--mut)}
@media(max-width:700px){.tabs{overflow-x:auto;flex-wrap:nowrap;padding-bottom:5px}.chip{white-space:nowrap}.in{gap:10px;flex-wrap:wrap}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}main{padding:10px}.report-filters{grid-template-columns:repeat(2,minmax(0,1fr))}.report-actions{grid-column:1/-1}.report-row{grid-template-columns:1fr 1fr;gap:6px}.report-row .product-name{grid-column:1/-1}.report-head{padding:12px}}
</style>
<header><div class="in"><b>⚙️ لوحة الإدارة</b><span><span id="me"></span> <a class="top" href="#" onclick="chpw();return false">🔑 كلمة السر</a> · <a class="top" href="/admin/logout">خروج</a> · <a class="top" href="/" target="_blank">المتجر ↗</a></span></div></header>
<main><div id="nb" hidden onclick="this.hidden=true"></div><div id="ab" class="gr"><h2 id="am"></h2></div><small id="wa" style="display:block;margin:0 0 10px"></small><div class="stats" id="st"></div>
<div class="tabs" id="tabs"><button class="chip on" data-t="o">الطلبات</button><button class="chip" data-t="p">المنتجات</button><button class="chip" data-t="k">المخزون</button><button class="chip" data-t="b">البنرات</button><button class="chip" data-t="s">الشعار</button><button class="chip" data-t="u">المستخدمون</button><button class="chip" data-t="r">تقارير المبيعات</button><button class="chip" data-t="a">سجل النشاط</button></div>
<div id="to"></div>
<div id="tp" hidden><div class="box"><h3 id="ft">إضافة منتج</h3><form id="fm"><input type="hidden" name="id">
<input name="name" placeholder="اسم المنتج" required><input name="purchase_price" type="number" step="any" min="0" placeholder="سعر الشراء (داخلي)" required><input name="price" type="number" step="any" min="0" placeholder="سعر البيع للزبون" required>
<input name="category" placeholder="التصنيف (مثال: كتب)"><input name="badge" placeholder="شارة على المنتج (مثال: جديد، خصم)"><input name="stock" type="number" min="0" placeholder="الكمية بالمخزون (فارغ = غير محدد)"><textarea name="desc" rows="2" placeholder="وصف قصير"></textarea>
<input name="image" type="file" accept="image/*"><select name="active"><option value="1">ظاهر بالمتجر</option><option value="0">مخفي</option></select>
<button>حفظ</button> <button type="button" class="g" onclick="rst()">جديد</button> <span id="m"></span></form></div><div class="pg" id="pl"></div></div>
<div id="tu" hidden><div class="box"><h3 id="ut">إضافة مستخدم</h3><form id="uf"><input type="hidden" name="id">
<input name="username" placeholder="اسم المستخدم (إنكليزي)" required><input name="password" type="password" placeholder="كلمة السر (6 أحرف على الأقل)">
<p style="margin:6px 0"><b>الأقسام اللي يكدر يشوفها:</b></p><div id="pm"></div>
<select name="active"><option value="1">فعّال</option><option value="0">موقوف</option></select>
<button>حفظ</button> <button type="button" class="g" onclick="rstU()">جديد</button> <span id="um"></span></form></div><div class="pg" id="ul"></div></div>
<div id="tk" hidden><div class="pg" id="kl"></div></div>
<div id="tb" hidden><div class="box"><h3>إضافة بنر متحرك</h3><form id="bf"><input name="title" placeholder="العنوان (مثال: خصومات الأسبوع)"><input name="subtitle" placeholder="نص صغير تحت العنوان">
<input name="link" placeholder="رابط عند الضغط (اختياري)"><input name="image" type="file" accept="image/*"><small>الأفضل صورة عريضة 1200×400. بدون صورة يظهر بنر ملون متحرك.</small><br><button>إضافة</button> <span id="bm"></span></form></div><div class="pg" id="bl"></div></div>
<div id="ts" hidden><div class="box"><h3>شعار المتجر</h3><form id="lg"><input name="image" type="file" accept="image/*" required><button>رفع الشعار</button></form></div></div>
<div id="tr" hidden><div class="box report-head"><h2>📊 تقارير المبيعات والأرباح</h2><p>حدد الفترة وحالة الطلب حتى تشوف نتائج أدق. المبيعات تخص المنتجات، والتوصيل ظاهر بشكل منفصل.</p><div class="report-filters"><label>من تاريخ<input type="date" id="reportFrom"></label><label>إلى تاريخ<input type="date" id="reportTo"></label><label>حالة الطلب<select id="reportStatus"><option value="">كل الحالات</option><option value="new">جديد</option><option value="shipping">قيد التوصيل</option><option value="done">مكتمل</option><option value="cancel">ملغي</option></select></label><label>بحث عن منتج<input id="reportProductSearch" placeholder="اسم المنتج..."></label><div class="report-actions"><button type="button" id="reportApply">عرض التقرير</button> <button type="button" class="g" id="reportReset">مسح الفلاتر</button></div></div><small id="reportRange"></small></div><div id="reportSummary" class="stats"></div><div class="box"><h3>📌 ملخص حسب حالة الطلب</h3><div id="reportStatuses"></div></div><div class="box"><h3>🏆 تفاصيل المنتجات</h3><div id="reportProducts"></div></div><div class="box"><small id="reportNote"></small></div></div>
<div id="ta" hidden><div class="box"><h3>سجل تحركات المستخدمين (آخر 500 عملية)</h3><p>السجل يبدأ من تفعيل هذه النسخة؛ لا يمكن إنشاء سجل تاريخي لعمليات لم تكن مسجلة سابقاً.</p><div id="activityRows"></div></div></div></main>
<script>
const $=s=>document.querySelector(s),E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ST={new:'جديد',shipping:'قيد التوصيل',done:'مكتمل',cancel:'ملغي'},S=o=>o.status||'new';
const ph=p=>{p=String(p).replace(/[^0-9]/g,'');return p.startsWith('0')?'964'+p.slice(1):p};
let P=[],O=[],B=[],U=[],AM=[],ai=0,LAST=null,REP=null,ACT=[];const ME=__ME__;
const can=k=>ME.owner||ME.perms.includes(k),J=async u=>{const r=await fetch(u);return r.ok?r.json():[]};
const PM={orders:'الطلبات',products:'المنتجات',stock:'المخزون',banners:'البنرات',logo:'الشعار'},TABS={o:'orders',p:'products',k:'stock',b:'banners',s:'logo',u:'owner',r:'owner',a:'owner'};const LOW=__LOW__;const LS=p=>p.stock!=null&&p.stock<=LOW;
async function load(){P=can('products')||can('stock')?await J('/admin/api/products'):[];O=can('orders')?await J('/admin/api/orders'):[];B=can('banners')?await J('/admin/api/banners'):[];if(ME.owner)U=await J('/admin/api/users');
const mx=O.reduce((a,o)=>Math.max(a,o.id),0);if(LAST!==null&&mx>LAST)alertNew(O.filter(o=>o.id>LAST));LAST=mx;
try{if(!can('orders'))throw 0;const w=await (await fetch('/admin/api/wa')).json();$('#wa').textContent=!w.configured?'ℹ️ إشعار واتساب التلقائي غير مفعّل، التنبيه يوصلك هنا بالداشبورد فقط':w.ok===false?'⚠️ آخر إرسال واتساب فشل: '+w.err:'✅ إشعارات واتساب مفعّلة'}catch(e){}
draw();drawB();drawK();drawU();if(ME.owner){loadReports();loadActivity()}}
function alertNew(n){const o=n[0];$('#nb').textContent=`🔔 طلب جديد #${o.id} من ${o.name} - ${o.city} - ${o.total.toLocaleString('en')}${n.length>1?' (+'+(n.length-1)+' طلبات أخرى)':''}`;$('#nb').hidden=false;
try{const a=new (window.AudioContext||window.webkitAudioContext)(),g=a.createGain(),s=a.createOscillator();s.connect(g);g.connect(a.destination);s.frequency.value=880;g.gain.value=.15;s.start();s.stop(a.currentTime+.3)}catch(e){}
document.title='🔔 ('+n.length+') طلب جديد';setTimeout(()=>{document.title='الإدارة'},8000)}
function draw(){const sales=O.filter(o=>S(o)=='done').reduce((a,o)=>a+o.total,0);
AM=['📦 عندك '+O.filter(o=>S(o)=='new').length+' طلب جديد بانتظارك','💰 مبيعات مكتملة: '+sales.toLocaleString('en'),'🛍️ '+P.length+' منتج بالمتجر','🖼️ '+B.length+' بنر متحرك'].concat(P.filter(LS).length?['⚠️ '+P.filter(LS).length+' منتج قارب ينفد أو نفد']:[]);AM=AM.filter((m,i)=>can(['orders','orders','products','banners','stock'][i]));if(!AM.length)AM=['👋 أهلاً '+ME.name];if(!$('#am').textContent)$('#am').textContent=AM[0];
$('#st').innerHTML=[['الطلبات',O.length],['جديدة',O.filter(o=>S(o)=='new').length],['مبيعات مكتملة',sales.toLocaleString('en')],['المنتجات',P.length],['قاربت تنفد',P.filter(LS).length]].filter((x,i)=>can(['orders','orders','orders','products','stock'][i])).map(x=>`<div class="stat"><b>${x[1]}</b><small>${x[0]}</small></div>`).join('');
$('#to').innerHTML=O.map(o=>`<div class="oc"><div class="r"><b>#${o.id}</b><small>${E(o.created)}</small><span class="bd s-${S(o)}">${ST[S(o)]}</span></div>
<div><b>${E(o.name)}</b> · ${E(o.phone)}<br>${E(o.city)} - ${E(o.address)}${o.notes?`<br><i>${E(o.notes)}</i>`:''}</div><pre>${E(o.items)}</pre>
<div class="r"><b>${o.total.toLocaleString('en')}</b><select style="width:auto" onchange="st(${o.id},this.value)">${Object.keys(ST).map(k=>`<option value="${k}"${k==S(o)?' selected':''}>${ST[k]}</option>`).join('')}</select></div>
<a class="lk" href="tel:${E(o.phone)}">📞 اتصال</a><a class="lk" target="_blank" href="https://wa.me/${ph(o.phone)}">💬 واتساب</a><button class="d" style="float:left;padding:6px 12px" onclick="delO(${o.id},'${S(o)}')">🗑️ حذف</button></div>`).join('')||'<p>لا توجد طلبات بعد</p>';
$('#pl').innerHTML=P.map(p=>`<div class="box">${p.image?`<img src="/uploads/${E(p.image)}" alt="">`:''}<b>${E(p.name)}</b><br>شراء: ${Number(p.purchase_price||0).toLocaleString('en')} · بيع: ${Number(p.price).toLocaleString('en')} ${p.active?'':'<span class="bd">مخفي</span>'}<br><small>${E(p.category)}</small>
<div style="margin-top:8px"><button class="g" onclick="ed(${p.id})">تعديل</button> <button class="d" onclick="del(${p.id})">حذف</button></div></div>`).join('')||'<p>لا توجد منتجات</p>'}
async function delO(id,s){if(!confirm('حذف الطلب #'+id+' نهائياً؟'+(s=='new'||s=='shipping'?' (ترجع كمياته للمخزون)':'')))return;
await fetch(`/admin/api/orders/${id}/delete`,{method:'POST'});load()}
async function st(id,s){await fetch(`/admin/api/orders/${id}/status`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});load()}
function ed(id){const p=P.find(x=>x.id==id),F=$('#fm');F.id.value=p.id;F.name.value=p.name;F.price.value=p.price;F.purchase_price.value=p.purchase_price||0;F.category.value=p.category;F.desc.value=p.desc;F.active.value=p.active;F.badge.value=p.badge||'';F.stock.value=p.stock==null?'':p.stock;$('#ft').textContent='تعديل منتج';scrollTo(0,0)}
function rst(){$('#fm').reset();$('#fm').id.value='';$('#ft').textContent='إضافة منتج'}
async function del(id){if(confirm('تحذف المنتج؟')){await fetch(`/admin/api/products/${id}/delete`,{method:'POST'});load()}}
$('#tabs').onclick=e=>{const t=e.target.dataset.t;if(!t)return;[...$('#tabs').children].forEach(b=>b.classList.toggle('on',b===e.target));['o','p','k','b','s','u','r','a'].forEach(k=>$('#t'+k).hidden=k!=t);if(t==='r')loadReports();if(t==='a')loadActivity()};
$('#fm').onsubmit=async e=>{e.preventDefault();const r=await fetch('/admin/api/products',{method:'POST',body:new FormData(e.target)});const j=await r.json();
$('#m').textContent=r.ok?'تم الحفظ ✓':j.error;if(r.ok){rst();load()}};
$('#lg').onsubmit=async e=>{e.preventDefault();const r=await fetch('/admin/api/logo',{method:'POST',body:new FormData(e.target)});alert(r.ok?'تم رفع الشعار':(await r.json()).error)};
function drawK(){const T=P.filter(p=>p.stock!=null),mx=Math.max(LOW*4,...T.map(p=>p.stock));
$('#kl').innerHTML=P.map(p=>{const s=p.stock,[t,c]=s==null?['غير محدد','']:s<=0?['نفدت','s-cancel']:s<=LOW?['قارب ينفد','s-new']:['متوفر','s-done'];
return `<div class="box"><div class="r" style="border:0"><b>${E(p.name)}</b><span class="bd ${c}">${t}</span></div>
<div class="bar"><i class="${c}" style="width:${s==null?0:Math.min(100,s/mx*100)}%"></i></div>
<div class="r" style="border:0"><b style="font-size:24px">${s==null?'∞':s}</b><span><button class="g" onclick="sk(${p.id},-1)">−</button> <button class="g" onclick="sk(${p.id},1)">+</button> <button class="g" onclick="sk(${p.id},0,1)">تحديد</button></span></div></div>`}).join('')||'<p>لا توجد منتجات</p>'}
async function sk(id,d,set){let b={delta:d};if(set){const v=prompt('الكمية المتوفرة حالياً؟ (فارغ = غير محدد)');if(v===null)return;b={set:v}}
await fetch(`/admin/api/products/${id}/stock`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});load()}
function drawU(){if(!ME.owner)return;$('#ul').innerHTML=U.map(u=>`<div class="box"><b>${E(u.username)}</b> ${u.role=='owner'?'<span class="bd s-done">المدير</span>':u.active?'':'<span class="bd s-cancel">موقوف</span>'}<br><small>${u.role=='owner'?'كل الصلاحيات':u.perms.map(p=>PM[p]).join('، ')||'بدون صلاحيات'}</small>
<div style="margin-top:8px"><button class="g" onclick="edU(${u.id})">تعديل</button>${u.role=='owner'?'':` <button class="d" onclick="delU(${u.id})">حذف</button>`}</div></div>`).join('')}
function edU(id){const u=U.find(x=>x.id==id),F=$('#uf');F.id.value=u.id;F.username.value=u.username;F.username.readOnly=true;F.password.value='';F.active.value=u.active?1:0;
document.querySelectorAll('#pm input').forEach(x=>x.checked=u.role=='owner'||u.perms.includes(x.value));$('#ut').textContent='تعديل مستخدم';F.password.placeholder='كلمة سر جديدة (اتركها فارغة لعدم التغيير)';scrollTo(0,0)}
function rstU(){const F=$('#uf');F.reset();F.id.value='';F.username.readOnly=false;F.password.placeholder='كلمة السر (6 أحرف على الأقل)';$('#ut').textContent='إضافة مستخدم'}
async function delU(id){if(confirm('تحذف المستخدم؟')){await fetch(`/admin/api/users/${id}/delete`,{method:'POST'});load()}}
async function chpw(){const o=prompt('كلمة السر الحالية'),n=o&&prompt('كلمة السر الجديدة (6 أحرف على الأقل)');if(!n)return;
const r=await fetch('/admin/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})});alert(r.ok?'تم تغيير كلمة السر':(await r.json()).error)}
function setupTabs(){const ok=[];[...$('#tabs').children].forEach(b=>{const k=TABS[b.dataset.t],a=k=='owner'?ME.owner:can(k);b.hidden=!a;if(a)ok.push(b)});
if(ok.length)ok[0].click();else $('#to').innerHTML='<p>ما عندك صلاحيات، تواصل مع المدير.</p>'}
function drawB(){$('#bl').innerHTML=B.map(b=>`<div class="box">${b.image?`<img src="/uploads/${E(b.image)}" alt="">`:'<div class="gr" style="height:110px;border-radius:8px;position:relative;overflow:hidden"></div>'}<b>${E(b.title)}</b><br><small>${E(b.subtitle)}</small><br><button class="d" style="margin-top:8px" onclick="delB(${b.id})">حذف</button></div>`).join('')||'<p>لا توجد بنرات، يظهر بنر افتراضي متحرك</p>'}
async function delB(id){if(confirm('تحذف البنر؟')){await fetch(`/admin/api/banners/${id}/delete`,{method:'POST'});load()}}
$('#bf').onsubmit=async e=>{e.preventDefault();const r=await fetch('/admin/api/banners',{method:'POST',body:new FormData(e.target)});const j=await r.json();$('#bm').textContent=r.ok?'تمت الإضافة ✓':j.error;if(r.ok){e.target.reset();load()}};
async function loadReports(){if(!ME.owner)return;try{const q=new URLSearchParams();if($('#reportFrom').value)q.set('from',$('#reportFrom').value);if($('#reportTo').value)q.set('to',$('#reportTo').value);if($('#reportStatus').value)q.set('status',$('#reportStatus').value);const r=await fetch('/admin/api/reports?'+q.toString());if(!r.ok)return;REP=await r.json();const t=REP.totals,fmt=n=>Number(n||0).toLocaleString('en',{maximumFractionDigits:2});
const from=$('#reportFrom').value,to=$('#reportTo').value,st=$('#reportStatus').selectedOptions[0]?.textContent||'كل الحالات';$('#reportRange').textContent=`الفترة: ${from||'من البداية'} ← ${to||'لليوم'} · الحالة: ${st} · عدد الطلبات: ${t.orders}`;
$('#reportSummary').innerHTML=[['📦 الطلبات ضمن الفلتر',t.orders],['💰 مبيعات المنتجات',fmt(t.revenue)+' '+REP.currency],['🧾 تكلفة الشراء',fmt(t.cost)+' '+REP.currency],['✨ الربح التقديري',fmt(t.profit)+' '+REP.currency],['✅ مبيعات المكتمل',fmt(t.completed_revenue)+' '+REP.currency],['📈 ربح المكتمل',fmt(t.completed_profit)+' '+REP.currency],['🚚 رسوم التوصيل',fmt(t.delivery)+' '+REP.currency]].map((x,i)=>`<div class="stat"><small>${x[0]}</small><b>${x[1]}</b></div>`).join('');
$('#reportStatuses').innerHTML=REP.statuses.map(x=>`<div class="report-row"><b class="product-name">${E(x.label)} <small>(${x.count} طلب)</small></b><span>مبيعات<br><b>${fmt(x.revenue)}</b></span><span>تكلفة<br><b>${fmt(x.cost)}</b></span><span>ربح<br><b class="${x.profit<0?'loss':'profit'}">${fmt(x.profit)}</b></span><span>توصيل<br><b>${fmt(x.delivery)}</b></span></div>`).join('')||'<p>لا توجد طلبات بهذه الفلاتر</p>';
const pq=($('#reportProductSearch').value||'').trim().toLowerCase(),products=REP.products.filter(x=>x.name.toLowerCase().includes(pq));$('#reportProducts').innerHTML=products.map(x=>`<div class="report-row"><b class="product-name">${E(x.name)}<br><small>الكمية: ${x.qty}</small></b><span>مبيعات<br><b>${fmt(x.revenue)}</b></span><span>تكلفة<br><b>${fmt(x.cost)}</b></span><span>ربح<br><b class="${x.profit<0?'loss':'profit'}">${fmt(x.profit)}</b></span><span>الكمية<br><b>${x.qty}</b></span></div>`).join('')||'<p>لا توجد منتجات مطابقة ضمن هذه الفترة</p>';
$('#reportNote').textContent=t.legacy_orders?'تنبيه: '+t.legacy_orders+' طلب/طلبات قديمة لم تحفظ سعر الشراء وقت الطلب؛ تكلفتها محسوبة تقديرياً من سعر الشراء الحالي.':'أسعار الشراء التاريخية محفوظة للطلبات الجديدة.';
}catch(e){$('#reportNote').textContent='تعذر تحميل التقرير.'}}
$('#reportApply').onclick=loadReports;$('#reportReset').onclick=()=>{$('#reportFrom').value='';$('#reportTo').value='';$('#reportStatus').value='';$('#reportProductSearch').value='';loadReports()};$('#reportProductSearch').oninput=()=>{if(REP){const fmt=n=>Number(n||0).toLocaleString('en',{maximumFractionDigits:2}),pq=$('#reportProductSearch').value.trim().toLowerCase();$('#reportProducts').innerHTML=REP.products.filter(x=>x.name.toLowerCase().includes(pq)).map(x=>`<div class="report-row"><b class="product-name">${E(x.name)}<br><small>الكمية: ${x.qty}</small></b><span>مبيعات<br><b>${fmt(x.revenue)}</b></span><span>تكلفة<br><b>${fmt(x.cost)}</b></span><span>ربح<br><b class="${x.profit<0?'loss':'profit'}">${fmt(x.profit)}</b></span><span>الكمية<br><b>${x.qty}</b></span></div>`).join('')||'<p>لا توجد منتجات مطابقة</p>'}};
async function loadActivity(){if(!ME.owner)return;try{const r=await fetch('/admin/api/activity');if(!r.ok)return;ACT=await r.json();$('#activityRows').innerHTML=ACT.map(x=>`<div class="r"><span><b>${E(x.username)}</b> · ${E(x.action)}<br><small>${E(x.created)} · ${E(x.details||'')}<br>${E(x.method)} ${E(x.path)} · IP: ${E(x.ip||'-')}</small></span></div>`).join('')||'<p>لا توجد عمليات مسجلة بعد</p>'}catch(e){}}
setInterval(()=>{if(!AM.length)return;ai=(ai+1)%AM.length;const m=$('#am');m.style.animation='none';m.offsetHeight;m.style.animation='';m.textContent=AM[ai]},3500);
$('#pm').innerHTML=Object.keys(PM).map(k=>`<label style="display:block;margin:4px 0"><input type="checkbox" style="width:auto;margin:0 0 0 8px" value="${k}">${PM[k]}</label>`).join('');
$('#uf').onsubmit=async e=>{e.preventDefault();const F=e.target,perms=[...F.querySelectorAll('#pm input:checked')].map(x=>x.value);
const r=await fetch('/admin/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:F.id.value,username:F.username.value,password:F.password.value,perms,active:F.active.value})});
const j=await r.json();$('#um').textContent=r.ok?'تم الحفظ ✓':j.error;if(r.ok){rstU();load()}};
$('#me').textContent='👤 '+ME.name;setupTabs();
setInterval(load,15000);
load();
</script></html>""".replace("__CSS__", CSS)


@app.get("/")
def index():
    return Response(PAGE.replace("__COLOR__", COLOR).replace("__A1__", A1).replace("__A2__", A2), mimetype="text/html")


init()
if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
