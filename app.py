import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
import re
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
 
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
 
db_url = os.environ.get('DATABASE_URL', 'sqlite:///entrix.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
 
db = SQLAlchemy(app)
 
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_KEY', '')
QB_CLIENT_ID = os.environ.get('QB_CLIENT_ID', '')
QB_CLIENT_SECRET = os.environ.get('QB_CLIENT_SECRET', '')
QB_REDIRECT_URI = os.environ.get('QB_REDIRECT_URI', 'http://localhost:5000/qb/callback')
 
QB_SANDBOX_BASE = 'https://sandbox-quickbooks.api.intuit.com'
QB_PROD_BASE = 'https://quickbooks.api.intuit.com'
TOKEN_URL = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
 
MIRA_TINS = [
    {'tin': '1234567GST501', 'description': 'General unregistered supplier (GST501)'},
    {'tin': '1234567GST502', 'description': 'Retail unregistered supplier (GST502)'},
    {'tin': '1234567GST503', 'description': 'Service unregistered supplier (GST503)'},
    {'tin': '1234567GST504', 'description': 'Import unregistered supplier (GST504)'},
    {'tin': '1234567GST505', 'description': 'Export unregistered supplier (GST505)'},
]
 
QB_ACCOUNTS = [
    {'name': 'Office supplies', 'code': '6200', 'qb_id': '52'},
    {'name': 'Advertising', 'code': '6100', 'qb_id': '7'},
    {'name': 'Professional services', 'code': '6300', 'qb_id': '53'},
    {'name': 'Utilities', 'code': '6400', 'qb_id': '54'},
    {'name': 'Travel', 'code': '6600', 'qb_id': '55'},
    {'name': 'Meals & entertainment', 'code': '6500', 'qb_id': '13'},
    {'name': 'Software subscriptions', 'code': '6250', 'qb_id': '52'},
    {'name': 'Sales revenue', 'code': '4000', 'qb_id': '79'},
    {'name': 'Taxes & duties', 'code': '6700', 'qb_id': '56'},
    {'name': 'Other expense', 'code': '6900', 'qb_id': '57'},
]
 
 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    company = db.Column(db.String(150))
    country = db.Column(db.String(50), default='Maldives')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    qb_access_token = db.Column(db.Text)
    qb_refresh_token = db.Column(db.Text)
    qb_realm_id = db.Column(db.String(50))
    qb_environment = db.Column(db.String(20), default='sandbox')
    vendors = db.relationship('Vendor', backref='user', lazy=True)
    bills = db.relationship('Bill', backref='user', lazy=True)
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
 
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
 
 
class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    tin = db.Column(db.String(50))
    tin_exempt = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    address = db.Column(db.Text)
    currency = db.Column(db.String(10), default='MVR')
    payment_terms = db.Column(db.String(50), default='Net 30')
    qb_vendor_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bills = db.relationship('Bill', backref='vendor', lazy=True)
 
 
class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    invoice_number = db.Column(db.String(100))
    invoice_date = db.Column(db.Date)
    due_date = db.Column(db.Date)
    currency = db.Column(db.String(10), default='MVR')
    subtotal = db.Column(db.Float, default=0)
    tax = db.Column(db.Float, default=0)
    total = db.Column(db.Float, default=0)
    account = db.Column(db.String(100))
    notes = db.Column(db.Text)
    line_items = db.Column(db.Text)
    status = db.Column(db.String(20), default='draft')
    qb_bill_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
 
 
with app.app_context():
    try:
        db.create_all()
        print('Database tables created successfully')
    except Exception as e:
        print(f'Database error: {e}')
 
 
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated
 
 
def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None
 
 
def refresh_qb_token(user):
    creds = base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data = urllib.parse.urlencode({
        'grant_type': 'refresh_token',
        'refresh_token': user.qb_refresh_token
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, headers={
        'Authorization': f'Basic {creds}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    })
    try:
        with urllib.request.urlopen(req) as resp:
            tokens = json.loads(resp.read())
            user.qb_access_token = tokens['access_token']
            if 'refresh_token' in tokens:
                user.qb_refresh_token = tokens['refresh_token']
            db.session.commit()
            return True
    except:
        return False
 
 
def qb_api(user, method, path, body=None):
    base = QB_SANDBOX_BASE if user.qb_environment == 'sandbox' else QB_PROD_BASE
    url = f'{base}/v3/company/{user.qb_realm_id}{path}?minorversion=65'
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {user.qb_access_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        if e.code == 401:
            refresh_qb_token(user)
            req.headers['Authorization'] = f'Bearer {user.qb_access_token}'
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read()), resp.status
        raise Exception(f'QB API error {e.code}: {e.read().decode()}')
 
 
def find_or_create_qb_vendor(user, vendor):
    if vendor.qb_vendor_id:
        return vendor.qb_vendor_id
    try:
        result, _ = qb_api(user, 'POST', '/vendor', {
            'DisplayName': vendor.name,
            'TaxIdentifier': vendor.tin or ''
        })
        vendor.qb_vendor_id = result['Vendor']['Id']
        db.session.commit()
        return vendor.qb_vendor_id
    except:
        return None
 
 
def post_bill_to_qb(user, bill, vendor):
    vendor_id = find_or_create_qb_vendor(user, vendor)
    if not vendor_id:
        return None, 'Could not create vendor in QuickBooks'
 
    account_id = '57'
    for acct in QB_ACCOUNTS:
        if f"{acct['name']} ({acct['code']})" == bill.account:
            account_id = acct['qb_id']
            break
 
    line_items = json.loads(bill.line_items or '[]')
    lines = []
    for item in line_items:
        lines.append({
            'Amount': float(item.get('total') or 0),
            'DetailType': 'AccountBasedExpenseLineDetail',
            'Description': item.get('description', ''),
            'AccountBasedExpenseLineDetail': {
                'AccountRef': {'value': account_id},
                'BillableStatus': 'NotBillable'
            }
        })
 
    if not lines:
        lines.append({
            'Amount': float(bill.total or 0),
            'DetailType': 'AccountBasedExpenseLineDetail',
            'AccountBasedExpenseLineDetail': {
                'AccountRef': {'value': account_id},
                'BillableStatus': 'NotBillable'
            }
        })
 
    payload = {
        'VendorRef': {'value': vendor_id},
        'TxnDate': bill.invoice_date.strftime('%Y-%m-%d') if bill.invoice_date else datetime.utcnow().strftime('%Y-%m-%d'),
        'DocNumber': bill.invoice_number or '',
        'PrivateNote': bill.notes or '',
        'Line': lines,
        'CurrencyRef': {'value': 'USD'}
    }
 
    if bill.due_date:
        payload['DueDate'] = bill.due_date.strftime('%Y-%m-%d')
 
    try:
        result, _ = qb_api(user, 'POST', '/bill', payload)
        return result['Bill']['Id'], None
    except Exception as e:
        return None, str(e)
 
 
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))
 
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        company = request.form.get('company', '').strip()
        country = request.form.get('country', 'Maldives')
 
        if not name or not email or not password:
            flash('Please fill in all required fields', 'error')
            return render_template('register.html')
 
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists', 'error')
            return render_template('register.html')
 
        user = User(name=name, email=email, company=company, country=country)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
 
        session['user_id'] = user.id
        session['user_name'] = user.name
        session.permanent = True
        flash(f'Welcome to Entrix, {name}!', 'success')
        return redirect(url_for('dashboard'))
 
    return render_template('register.html')
 
 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
 
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session.permanent = True
            return redirect(url_for('dashboard'))
 
        flash('Invalid email or password', 'error')
    return render_template('login.html')
 
 
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
 
 
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    recent_bills = Bill.query.filter_by(user_id=user.id).order_by(Bill.created_at.desc()).limit(10).all()
    vendor_count = Vendor.query.filter_by(user_id=user.id).count()
    bill_count = Bill.query.filter_by(user_id=user.id).count()
    posted_count = Bill.query.filter_by(user_id=user.id, status='posted').count()
    total_amount = db.session.query(db.func.sum(Bill.total)).filter_by(user_id=user.id).scalar() or 0
    return render_template('dashboard.html', user=user, recent_bills=recent_bills,
                           vendor_count=vendor_count, bill_count=bill_count,
                           posted_count=posted_count, total_amount=total_amount)
 
 
@app.route('/bills')
@login_required
def bills():
    user = current_user()
    return render_template('bills.html', user=user, accounts=QB_ACCOUNTS, mira_tins=MIRA_TINS)
 
 
@app.route('/bank')
@login_required
def bank():
    user = current_user()
    return render_template('bank.html', user=user, accounts=QB_ACCOUNTS)
 
 
@app.route('/vendors')
@login_required
def vendors():
    user = current_user()
    vendor_list = Vendor.query.filter_by(user_id=user.id).order_by(Vendor.name).all()
    return render_template('vendors.html', user=user, vendors=vendor_list)
 
 
@app.route('/settings')
@login_required
def settings():
    user = current_user()
    return render_template('settings.html', user=user)
 
 
@app.route('/api/extract-bill', methods=['POST'])
@login_required
def api_extract_bill():
    user = current_user()
    if not ANTHROPIC_KEY:
        return jsonify({'ok': False, 'error': 'Anthropic API key not configured'})
 
    data = request.get_json()
    file_b64 = data.get('file')
    media_type = data.get('media_type', 'image/jpeg')
    is_pdf = media_type == 'application/pdf'
 
    accounts_list = ', '.join([f"{a['name']} ({a['code']})" for a in QB_ACCOUNTS])
 
    prompt = f'''You are an expert accountant. Analyse this bill/invoice/receipt and extract all data.
Return ONLY valid JSON with no extra text:
{{"vendor":"name","invoice_number":"num","invoice_date":"YYYY-MM-DD","due_date":"YYYY-MM-DD","currency":"MVR","tin":"tin number or null","subtotal":0.00,"tax":0.00,"total":0.00,"suggested_account":"Office supplies (6200)","notes":"","line_items":[{{"description":"item","quantity":1,"unit_price":0.00,"total":0.00}}]}}
Use null for missing fields. Extract TIN/tax number if present on document.
suggested_account must be one of: {accounts_list}'''
 
    content_item = (
        {'type': 'document', 'source': {'type': 'base64', 'media_type': 'application/pdf', 'data': file_b64}}
        if is_pdf else
        {'type': 'image', 'source': {'type': 'base64', 'media_type': media_type, 'data': file_b64}}
    )
 
    try:
        req_body = json.dumps({
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'messages': [{'role': 'user', 'content': [content_item, {'type': 'text', 'text': prompt}]}]
        }).encode()
 
        req = urllib.request.Request('https://api.anthropic.com/v1/messages',
            data=req_body,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01'
            })
 
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            text = result['content'][0]['text']
            match = re.search(r'\{[\s\S]*\}', text)
            if not match:
                return jsonify({'ok': False, 'error': 'Could not parse AI response'})
 
            extracted = json.loads(match.group())
 
            vendor_match = None
            if extracted.get('vendor'):
                vendor_list = Vendor.query.filter_by(user_id=user.id).all()
                name_lower = extracted['vendor'].lower()
                for v in vendor_list:
                    if v.name.lower() in name_lower or name_lower in v.name.lower():
                        vendor_match = {'id': v.id, 'name': v.name, 'tin': v.tin, 'tin_exempt': v.tin_exempt}
                        break
 
            return jsonify({
                'ok': True,
                'data': extracted,
                'vendor_match': vendor_match,
                'mira_tins': MIRA_TINS if user.country == 'Maldives' else []
            })
 
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})
 
 
@app.route('/api/extract-bank', methods=['POST'])
@login_required
def api_extract_bank():
    user = current_user()
    if not ANTHROPIC_KEY:
        return jsonify({'ok': False, 'error': 'Anthropic API key not configured'})
 
    data = request.get_json()
    file_b64 = data.get('file')
    media_type = data.get('media_type', 'image/jpeg')
    is_pdf = media_type == 'application/pdf'
 
    accounts_list = ', '.join([f"{a['name']} ({a['code']})" for a in QB_ACCOUNTS])
 
    prompt = f'''You are an expert accountant. Analyse this bank statement and extract ALL transactions.
Return ONLY valid JSON with no extra text:
{{"account":"name","period":"dates","transactions":[{{"date":"YYYY-MM-DD","description":"desc","amount":0.00,"type":"debit","suggested_account":"Utilities (6400)","confidence":"high"}}]}}
Negative amounts for debits, positive for credits. confidence is high or low.
suggested_account must be one of: {accounts_list}'''
 
    content_item = (
        {'type': 'document', 'source': {'type': 'base64', 'media_type': 'application/pdf', 'data': file_b64}}
        if is_pdf else
        {'type': 'image', 'source': {'type': 'base64', 'media_type': media_type, 'data': file_b64}}
    )
 
    try:
        req_body = json.dumps({
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'messages': [{'role': 'user', 'content': [content_item, {'type': 'text', 'text': prompt}]}]
        }).encode()
 
        req = urllib.request.Request('https://api.anthropic.com/v1/messages',
            data=req_body,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01'
            })
 
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            text = result['content'][0]['text']
            match = re.search(r'\{[\s\S]*\}', text)
            if not match:
                return jsonify({'ok': False, 'error': 'Could not parse AI response'})
            return jsonify({'ok': True, 'data': json.loads(match.group())})
 
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})
 
 
@app.route('/api/save-vendor', methods=['POST'])
@login_required
def api_save_vendor():
    user = current_user()
    data = request.get_json()
 
    existing = Vendor.query.filter_by(user_id=user.id, name=data.get('name')).first()
    if existing:
        existing.tin = data.get('tin') or existing.tin
        existing.tin_exempt = data.get('tin_exempt', False)
        existing.currency = data.get('currency', existing.currency)
        existing.payment_terms = data.get('payment_terms', existing.payment_terms)
        db.session.commit()
        return jsonify({'ok': True, 'vendor_id': existing.id, 'message': 'Vendor updated'})
 
    vendor = Vendor(
        user_id=user.id,
        name=data.get('name', ''),
        tin=data.get('tin'),
        tin_exempt=data.get('tin_exempt', False),
        email=data.get('email'),
        phone=data.get('phone'),
        address=data.get('address'),
        currency=data.get('currency', 'MVR'),
        payment_terms=data.get('payment_terms', 'Net 30')
    )
    db.session.add(vendor)
    db.session.commit()
    return jsonify({'ok': True, 'vendor_id': vendor.id, 'message': 'Vendor created'})
 
 
@app.route('/api/post-bill', methods=['POST'])
@login_required
def api_post_bill():
    user = current_user()
    data = request.get_json()
 
    vendor_id = data.get('vendor_id')
    vendor = Vendor.query.filter_by(id=vendor_id, user_id=user.id).first() if vendor_id else None
 
    if not vendor:
        v_name = data.get('vendor_name', 'Unknown')
        vendor = Vendor.query.filter_by(user_id=user.id, name=v_name).first()
        if not vendor:
            vendor = Vendor(
                user_id=user.id,
                name=v_name,
                tin=data.get('tin'),
                tin_exempt=data.get('tin_exempt', False),
                currency=data.get('currency', 'MVR')
            )
            db.session.add(vendor)
            db.session.flush()
 
    inv_date = None
    due_date = None
    try:
        if data.get('invoice_date'):
            inv_date = datetime.strptime(data['invoice_date'], '%Y-%m-%d').date()
        if data.get('due_date'):
            due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
    except:
        pass
 
    inv_number = data.get('invoice_number', '')
 
    bill = Bill(
        user_id=user.id,
        vendor_id=vendor.id,
        invoice_number=inv_number,
        invoice_date=inv_date,
        due_date=due_date,
        currency=data.get('currency', 'MVR'),
        subtotal=float(data.get('subtotal') or 0),
        tax=float(data.get('tax') or 0),
        total=float(data.get('total') or 0),
        account=data.get('account', ''),
        notes=data.get('notes', ''),
        line_items=json.dumps(data.get('line_items', [])),
        status='draft'
    )
    db.session.add(bill)
    db.session.flush()
 
    qb_bill_id = None
    qb_error = None
    if user.qb_access_token and user.qb_realm_id:
        qb_bill_id, qb_error = post_bill_to_qb(user, bill, vendor)
        if qb_bill_id:
            bill.qb_bill_id = qb_bill_id
            bill.status = 'posted'
        else:
            bill.status = 'saved'
    else:
        bill.status = 'saved'
 
    db.session.commit()
 
    return jsonify({
        'ok': True,
        'bill_id': bill.id,
        'qb_bill_id': qb_bill_id,
        'qb_error': qb_error,
        'status': bill.status,
        'message': 'Bill saved to Entrix' + (f' and posted to QuickBooks (ID: {qb_bill_id})' if qb_bill_id else ' (saved to Entrix only)')
    })
 
 
@app.route('/api/vendors/search')
@login_required
def api_vendors_search():
    user = current_user()
    q = request.args.get('q', '').lower()
    vendor_list = Vendor.query.filter_by(user_id=user.id).all()
    results = [{'id': v.id, 'name': v.name, 'tin': v.tin, 'tin_exempt': v.tin_exempt}
               for v in vendor_list if q in v.name.lower()]
    return jsonify(results)
 
 
@app.route('/api/status')
@login_required
def api_status():
    user = current_user()
    return jsonify({
        'ok': True,
        'qb_connected': bool(user.qb_access_token and user.qb_realm_id),
        'qb_environment': user.qb_environment,
        'anthropic_configured': bool(ANTHROPIC_KEY)
    })
 
 
@app.route('/qb/connect')
@login_required
def qb_connect():
    state = secrets.token_hex(16)
    session['qb_state'] = state
    auth_url = (
        'https://appcenter.intuit.com/connect/oauth2'
        f'?client_id={QB_CLIENT_ID}'
        f'&redirect_uri={urllib.parse.quote(QB_REDIRECT_URI)}'
        f'&response_type=code'
        f'&scope=com.intuit.quickbooks.accounting'
        f'&state={state}'
    )
    return redirect(auth_url)
 
 
@app.route('/qb/callback')
@login_required
def qb_callback():
    user = current_user()
    code = request.args.get('code')
    realm_id = request.args.get('realmId')
    state = request.args.get('state')
 
    if state != session.get('qb_state'):
        flash('Invalid state — please try connecting again', 'error')
        return redirect(url_for('settings'))
 
    creds = base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data = urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': QB_REDIRECT_URI
    }).encode()
 
    req = urllib.request.Request(TOKEN_URL, data=data, headers={
        'Authorization': f'Basic {creds}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    })
 
    try:
        with urllib.request.urlopen(req) as resp:
            tokens = json.loads(resp.read())
            user.qb_access_token = tokens['access_token']
            user.qb_refresh_token = tokens['refresh_token']
            user.qb_realm_id = realm_id
            user.qb_environment = 'sandbox'
            db.session.commit()
            flash('QuickBooks connected successfully!', 'success')
    except Exception as e:
        flash(f'QuickBooks connection failed: {str(e)}', 'error')
 
    return redirect(url_for('settings'))
 
 
@app.route('/qb/disconnect')
@login_required
def qb_disconnect():
    user = current_user()
    user.qb_access_token = None
    user.qb_refresh_token = None
    user.qb_realm_id = None
    db.session.commit()
    flash('QuickBooks disconnected', 'success')
    return redirect(url_for('settings'))
 
 
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
 
