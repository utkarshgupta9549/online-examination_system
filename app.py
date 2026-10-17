from flask import Flask, render_template, request, jsonify, session, redirect
import hashlib, os, csv, io, json, secrets, smtplib, sys, urllib.parse, urllib.request
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'examportal_dev_secret_change_in_prod')

# ── Config (all loaded from .env) ──────────────────────
MONGODB_URI = os.environ.get('MONGODB_URI', '')
MONGODB_DB  = os.environ.get('MONGODB_DB', 'examportal')

GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI  = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
if GOOGLE_CLIENT_ID.startswith('your_'):
    GOOGLE_CLIENT_ID = ''

SMTP_EMAIL    = os.environ.get('SMTP_EMAIL', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
if SMTP_EMAIL.startswith('your_') or SMTP_PASSWORD.startswith('your_'):
    SMTP_EMAIL = SMTP_PASSWORD = ''
SMTP_HOST     = 'smtp.gmail.com'
SMTP_PORT     = 587

OTP_EXPIRY_SECONDS = 600  # 10 minutes

# ── MongoDB ────────────────────────────────────────────
_client = None
db = None

def now_str():
    """UTC timestamp in the same format SQLite's datetime('now') used."""
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

def next_id(name):
    """Auto-increment integer IDs (keeps URLs/frontend identical to the SQLite version)."""
    doc = db.counters.find_one_and_update(
        {'_id': name}, {'$inc': {'seq': 1}},
        upsert=True, return_document=ReturnDocument.AFTER)
    return doc['seq']

def init_db():
    global _client, db
    if not MONGODB_URI:
        print('\n[ERROR] MONGODB_URI is empty. Open the .env file and set it.\n')
        sys.exit(1)
    _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10000)
    try:
        _client.admin.command('ping')
    except Exception as e:
        print('\n[ERROR] Could not connect to MongoDB:\n  ', e)
        print('\nCommon fixes:')
        print('  1. MongoDB Atlas -> Network Access -> Add IP Address -> "Allow access from anywhere" (0.0.0.0/0)')
        print('  2. Check the username/password in MONGODB_URI (.env)')
        print('  3. Check your internet connection\n')
        sys.exit(1)
    db = _client[MONGODB_DB]
    db.users.create_index('email', unique=True)
    db.otp_codes.create_index([('email', ASCENDING), ('purpose', ASCENDING)])
    db.student_groups.create_index('teacher_id')
    db.tests.create_index('teacher_id')
    db.questions.create_index('test_id')
    db.test_assignments.create_index([('test_id', ASCENDING), ('student_email', ASCENDING)], unique=True)
    db.test_assignments.create_index('student_email')
    db.attempts.create_index([('test_id', ASCENDING), ('student_id', ASCENDING)], unique=True)
    print(f'[DB] Connected to MongoDB, database "{MONGODB_DB}"')

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Not logged in'}), 401
            if role and session.get('role') != role:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def set_session(user):
    session['user_id'] = user['id']
    session['role']    = user['role']
    session['name']    = user['name']
    session['email']   = user['email']
    session['avatar']  = user.get('avatar') or ''

def clean_emails(emails):
    out, seen = [], set()
    for e in emails or []:
        e = (e or '').strip().lower()
        if e and e not in seen:
            seen.add(e); out.append(e)
    return out

def get_user(email):
    return db.users.find_one({'email': email}, {'_id': 0})

# ── OTP helpers ────────────────────────────────────────
def generate_otp():
    return str(secrets.randbelow(900000) + 100000)   # 6-digit

def save_otp(email, code, purpose):
    email = email.lower()
    expires = (datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS)).isoformat()
    db.otp_codes.delete_many({'email': email, 'purpose': purpose})
    db.otp_codes.insert_one({'email': email, 'code': code, 'purpose': purpose,
                             'expires_at': expires, 'used': 0})

def verify_otp(email, code, purpose):
    row = db.otp_codes.find_one({'email': email.lower(), 'purpose': purpose, 'used': 0},
                                sort=[('_id', -1)])
    if not row:
        return False, 'Invalid OTP'
    if datetime.utcnow().isoformat() > row['expires_at']:
        return False, 'OTP expired'
    if row['code'] != code:
        return False, 'Wrong OTP'
    db.otp_codes.update_one({'_id': row['_id']}, {'$set': {'used': 1}})
    return True, 'OK'

def send_otp_email(to_email, code, purpose):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print(f"\n{'='*40}\nOTP for {to_email} [{purpose}]: {code}\nExpires in 10 minutes\n{'='*40}\n")
        return False   # False = dev mode, shows yellow warning on page

    print(f"[SMTP] Sending OTP to {to_email} via {SMTP_EMAIL} ...")
    try:
        subject_map = {'verify': 'Verify your ExamPortal account',
                       'login':  'Your ExamPortal login OTP'}
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject_map.get(purpose, 'ExamPortal OTP')
        msg['From']    = f'ExamPortal <{SMTP_EMAIL}>'
        msg['To']      = to_email
        html = f"""
        <div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;padding:32px">
          <div style="background:linear-gradient(135deg,#1E1B4B,#4F46E5);border-radius:12px;padding:28px;text-align:center;color:#fff;margin-bottom:24px">
            <h1 style="margin:0;font-size:22px">ExamPortal</h1>
          </div>
          <h2 style="color:#1E293B">Your OTP Code</h2>
          <p style="color:#64748B">Use the code below to {'verify your email' if purpose=='verify' else 'log in'}.</p>
          <div style="background:#EEF2FF;border-radius:10px;padding:22px;text-align:center;margin:20px 0">
            <span style="font-size:36px;font-weight:800;letter-spacing:10px;color:#4F46E5">{code}</span>
          </div>
          <p style="color:#64748B;font-size:13px">This code expires in <strong>10 minutes</strong>. Do not share it.</p>
        </div>"""
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(SMTP_EMAIL, SMTP_PASSWORD)
            s.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print(f"[SMTP] OK - OTP sent successfully to {to_email}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("[SMTP ERROR] Authentication failed! Check SMTP_EMAIL and SMTP_PASSWORD in .env")
        print("             Make sure you used a Gmail APP PASSWORD (not your real password).")
        print("             Get one at: https://myaccount.google.com/apppasswords")
        return False
    except smtplib.SMTPException as e:
        print(f"[SMTP ERROR] SMTP error: {e}")
        return False
    except Exception as e:
        print(f"[SMTP ERROR] Unexpected error: {e}")
        return False

# ── Google OAuth helpers ───────────────────────────────
GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_INFO_URL  = 'https://www.googleapis.com/oauth2/v2/userinfo'

def google_auth_url(state, role):
    params = {
        'client_id':     GOOGLE_CLIENT_ID,
        'redirect_uri':  GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope':         'openid email profile',
        'state':         f"{state}:{role}",
        'access_type':   'offline',
    }
    return GOOGLE_AUTH_URL + '?' + urllib.parse.urlencode(params)

def google_exchange_code(code):
    data = urllib.parse.urlencode({
        'code': code, 'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }).encode()
    req = urllib.request.Request(GOOGLE_TOKEN_URL, data=data,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def google_get_userinfo(access_token):
    req = urllib.request.Request(GOOGLE_INFO_URL,
                                 headers={'Authorization': f'Bearer {access_token}'})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

# ══════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login')
def login_page():
    return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))

@app.route('/signup')
def signup_page():
    return render_template('signup.html', google_enabled=bool(GOOGLE_CLIENT_ID))

@app.route('/verify-email')
def verify_email_page():
    return render_template('verify_email.html')

@app.route('/teacher')
def teacher_dashboard():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')
    return render_template('teacher_dashboard.html')

@app.route('/student')
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect('/login')
    return render_template('student_dashboard.html')

@app.route('/exam/<int:tid>')
def exam_page(tid):
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect('/login')
    return render_template('exam.html', test_id=tid)

@app.route('/result/<int:attempt_id>')
def result_page(attempt_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect('/login')
    return render_template('result.html', attempt_id=attempt_id)

# ══════════════════════════════════════════════════════
# AUTH APIs — Email/Password + OTP
# ══════════════════════════════════════════════════════
@app.route('/api/signup', methods=['POST'])
def signup():
    d = request.json or {}
    if not all(k in d for k in ['name', 'email', 'password', 'role']):
        return jsonify({'error': 'Missing fields'}), 400
    if d['role'] not in ('teacher', 'student'):
        return jsonify({'error': 'Invalid role'}), 400
    if len(d['password']) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    email = d['email'].lower().strip()
    existing = get_user(email)
    if existing:
        if not existing.get('email_verified'):
            code = generate_otp()
            save_otp(email, code, 'verify')
            send_otp_email(email, code, 'verify')
            return jsonify({'pending_verify': True, 'email': email})
        return jsonify({'error': 'Email already registered'}), 409
    try:
        db.users.insert_one({
            'id': next_id('users'), 'name': d['name'], 'email': email,
            'password': hash_pw(d['password']), 'role': d['role'], 'google_id': None,
            'email_verified': 0, 'avatar': None, 'created_at': now_str()})
    except DuplicateKeyError:
        return jsonify({'error': 'Email already registered'}), 409
    code = generate_otp()
    save_otp(email, code, 'verify')
    sent = send_otp_email(email, code, 'verify')
    return jsonify({'pending_verify': True, 'email': email, 'dev': not sent})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp_route():
    d = request.json or {}
    email   = d.get('email', '').lower().strip()
    code    = d.get('code', '').strip()
    purpose = d.get('purpose', 'verify')
    ok, msg = verify_otp(email, code, purpose)
    if not ok:
        return jsonify({'error': msg}), 400
    if purpose == 'verify':
        db.users.update_one({'email': email}, {'$set': {'email_verified': 1}})
    user = get_user(email)
    if user:
        set_session(user)
        return jsonify({'role': user['role'], 'name': user['name']})
    return jsonify({'ok': True})

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    d = request.json or {}
    email   = d.get('email', '').lower().strip()
    purpose = d.get('purpose', 'verify')
    if not get_user(email):
        return jsonify({'error': 'Email not found'}), 404
    code = generate_otp()
    save_otp(email, code, purpose)
    sent = send_otp_email(email, code, purpose)
    return jsonify({'ok': True,
                    'dev_note': None if sent and SMTP_EMAIL else 'OTP printed to server console'})

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json or {}
    email    = d.get('email', '').lower().strip()
    password = d.get('password', '')
    user = db.users.find_one({'email': email, 'password': hash_pw(password)}, {'_id': 0})
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    if not user.get('email_verified'):
        code = generate_otp()
        save_otp(email, code, 'verify')
        send_otp_email(email, code, 'verify')
        return jsonify({'pending_verify': True, 'email': email})
    set_session(user)
    return jsonify({'role': user['role'], 'name': user['name']})

@app.route('/api/login-otp', methods=['POST'])
def login_otp_request():
    """Passwordless login: send OTP to email."""
    d = request.json or {}
    email = d.get('email', '').lower().strip()
    if not get_user(email):
        return jsonify({'error': 'No account with that email. Please sign up first.'}), 404
    code = generate_otp()
    save_otp(email, code, 'login')
    sent = send_otp_email(email, code, 'login')
    return jsonify({'ok': True,
                    'dev_note': None if sent and SMTP_EMAIL else 'OTP printed to server console (SMTP not configured)'})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/me')
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'id': session['user_id'], 'name': session['name'],
                    'email': session['email'], 'role': session['role'],
                    'avatar': session.get('avatar', '')})

# ══════════════════════════════════════════════════════
# GOOGLE OAUTH
# ══════════════════════════════════════════════════════
@app.route('/auth/google')
def google_login():
    if not GOOGLE_CLIENT_ID:
        return redirect('/login?error=Google+OAuth+not+configured')
    role  = request.args.get('role', 'student')
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    return redirect(google_auth_url(state, role))

@app.route('/auth/google/callback')
def google_callback():
    error = request.args.get('error')
    if error:
        return redirect(f'/login?error={urllib.parse.quote(error)}')

    code  = request.args.get('code', '')
    state = request.args.get('state', '')
    stored_state, _, role = state.partition(':')
    if stored_state != session.pop('oauth_state', None):
        return redirect('/login?error=Invalid+state')

    try:
        tokens   = google_exchange_code(code)
        userinfo = google_get_userinfo(tokens['access_token'])
    except Exception as e:
        return redirect(f'/login?error=Google+error:+{urllib.parse.quote(str(e))}')

    email     = userinfo.get('email', '').lower()
    name      = userinfo.get('name', email.split('@')[0])
    google_id = userinfo.get('id', '')
    avatar    = userinfo.get('picture', '')
    role      = role if role in ('teacher', 'student') else 'student'

    user = get_user(email)
    if user:
        db.users.update_one({'email': email},
                            {'$set': {'google_id': google_id, 'avatar': avatar, 'email_verified': 1}})
    else:
        db.users.insert_one({'id': next_id('users'), 'name': name, 'email': email, 'password': None,
                             'role': role, 'google_id': google_id, 'email_verified': 1,
                             'avatar': avatar, 'created_at': now_str()})
    user = get_user(email)
    set_session(user)
    return redirect('/teacher' if user['role'] == 'teacher' else '/student')

# ══════════════════════════════════════════════════════
# TEACHER APIs
# ══════════════════════════════════════════════════════
def save_questions(tid, questions):
    docs = [{'id': next_id('questions'), 'test_id': tid, 'question_text': q['question'],
             'correct_option': q['correct_option'], 'marks': q.get('marks', 1),
             'options': q['options']} for q in questions]
    if docs:
        db.questions.insert_many(docs)

def own_test(tid):
    return db.tests.find_one({'id': tid, 'teacher_id': session['user_id']}, {'_id': 0})

@app.route('/api/teacher/groups', methods=['GET'])
@login_required('teacher')
def get_groups():
    groups = db.student_groups.find({'teacher_id': session['user_id']}).sort('created_at', -1)
    return jsonify([{'id': g['id'], 'name': g['name'], 'created_at': g['created_at'],
                     'members': g.get('members', [])} for g in groups])

@app.route('/api/teacher/groups', methods=['POST'])
@login_required('teacher')
def create_group():
    d = request.json
    gid = next_id('student_groups')
    db.student_groups.insert_one({'id': gid, 'teacher_id': session['user_id'], 'name': d['name'],
                                  'members': clean_emails(d.get('emails', [])),
                                  'created_at': now_str()})
    return jsonify({'ok': True, 'id': gid})

@app.route('/api/teacher/groups/<int:gid>', methods=['PUT'])
@login_required('teacher')
def update_group(gid):
    d = request.json
    db.student_groups.update_one({'id': gid, 'teacher_id': session['user_id']},
                                 {'$set': {'name': d['name'],
                                           'members': clean_emails(d.get('emails', []))}})
    return jsonify({'ok': True})

@app.route('/api/teacher/groups/<int:gid>', methods=['DELETE'])
@login_required('teacher')
def delete_group(gid):
    db.student_groups.delete_one({'id': gid, 'teacher_id': session['user_id']})
    return jsonify({'ok': True})

@app.route('/api/teacher/tests', methods=['GET'])
@login_required('teacher')
def get_tests():
    result = []
    for t in db.tests.find({'teacher_id': session['user_id']}).sort('created_at', -1):
        result.append({'id': t['id'], 'title': t['title'], 'description': t.get('description'),
                       'duration_minutes': t.get('duration_minutes'), 'start_time': t.get('start_time'),
                       'end_time': t.get('end_time'), 'created_at': t['created_at'],
                       'question_count': db.questions.count_documents({'test_id': t['id']}),
                       'assigned_count': db.test_assignments.count_documents({'test_id': t['id']})})
    return jsonify(result)

@app.route('/api/teacher/tests', methods=['POST'])
@login_required('teacher')
def create_test():
    d = request.json
    tid = next_id('tests')
    db.tests.insert_one({'id': tid, 'teacher_id': session['user_id'], 'title': d['title'],
                         'description': d.get('description', ''),
                         'duration_minutes': d.get('duration_minutes', 30),
                         'start_time': d.get('start_time'), 'end_time': d.get('end_time'),
                         'created_at': now_str()})
    save_questions(tid, d.get('questions', []))
    return jsonify({'ok': True, 'id': tid})

@app.route('/api/teacher/tests/<int:tid>', methods=['GET'])
@login_required('teacher')
def get_test(tid):
    t = own_test(tid)
    if not t:
        return jsonify({'error': 'Not found'}), 404
    questions   = db.questions.find({'test_id': tid}).sort('id', 1)
    assignments = db.test_assignments.find({'test_id': tid})
    return jsonify({'id': t['id'], 'title': t['title'], 'description': t.get('description'),
                    'duration_minutes': t.get('duration_minutes'), 'start_time': t.get('start_time'),
                    'end_time': t.get('end_time'),
                    'questions': [{'id': q['id'], 'question': q['question_text'],
                                   'correct_option': q['correct_option'], 'marks': q['marks'],
                                   'options': q['options']} for q in questions],
                    'assigned_students': [a['student_email'] for a in assignments]})

@app.route('/api/teacher/tests/<int:tid>', methods=['PUT'])
@login_required('teacher')
def update_test(tid):
    d = request.json
    if not own_test(tid):
        return jsonify({'error': 'Not found'}), 404
    db.tests.update_one({'id': tid, 'teacher_id': session['user_id']},
                        {'$set': {'title': d['title'], 'description': d.get('description', ''),
                                  'duration_minutes': d.get('duration_minutes', 30),
                                  'start_time': d.get('start_time'), 'end_time': d.get('end_time')}})
    db.questions.delete_many({'test_id': tid})
    save_questions(tid, d.get('questions', []))
    return jsonify({'ok': True})

@app.route('/api/teacher/tests/<int:tid>', methods=['DELETE'])
@login_required('teacher')
def delete_test(tid):
    if not own_test(tid):
        return jsonify({'error': 'Not found'}), 404
    db.questions.delete_many({'test_id': tid})
    db.test_assignments.delete_many({'test_id': tid})
    db.attempts.delete_many({'test_id': tid})
    db.tests.delete_one({'id': tid, 'teacher_id': session['user_id']})
    return jsonify({'ok': True})

@app.route('/api/teacher/tests/<int:tid>/assign', methods=['POST'])
@login_required('teacher')
def assign_test(tid):
    d = request.json
    if not own_test(tid):
        return jsonify({'error': 'Not found'}), 404
    db.test_assignments.delete_many({'test_id': tid})
    docs = [{'test_id': tid, 'student_email': e, 'assigned_at': now_str()}
            for e in clean_emails(d.get('emails', []))]
    if docs:
        db.test_assignments.insert_many(docs)
    return jsonify({'ok': True})

@app.route('/api/teacher/tests/upload_csv', methods=['POST'])
@login_required('teacher')
def upload_csv():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    content = request.files['file'].read().decode('utf-8-sig')
    reader  = csv.DictReader(io.StringIO(content))
    questions = []
    for row in reader:
        opts, i = [], 1
        while True:
            v = row.get(f'option{i}') or row.get(f'Option{i}', '')
            if not v or not v.strip():
                break
            opts.append(v.strip()); i += 1
        q_text  = (row.get('question1') or row.get('Question1') or row.get('question', '') or '').strip()
        correct = int(row.get('answer') or row.get('Answer') or 1)
        marks   = int(row.get('marks') or row.get('Marks') or 1)
        if q_text:
            questions.append({'question': q_text, 'correct_option': correct, 'marks': marks, 'options': opts})
    return jsonify({'questions': questions})

def attempt_summary(a, test, user):
    return {'id': a['id'], 'test_id': a['test_id'], 'title': test['title'],
            'student_id': a['student_id'],
            'student_name': user['name'] if user else '(deleted user)',
            'student_email': user['email'] if user else '',
            'score': a.get('score', 0), 'total_marks': a.get('total_marks', 0),
            'submitted_at': a.get('submitted_at'), 'started_at': a.get('started_at')}

@app.route('/api/teacher/results', methods=['GET'])
@login_required('teacher')
def teacher_results():
    tests = {t['id']: t for t in db.tests.find({'teacher_id': session['user_id']})}
    attempts = list(db.attempts.find({'test_id': {'$in': list(tests)}}))
    users = {u['id']: u for u in db.users.find({'id': {'$in': list({a['student_id'] for a in attempts})}})}
    attempts.sort(key=lambda a: a.get('submitted_at') or '', reverse=True)
    return jsonify([attempt_summary(a, tests[a['test_id']], users.get(a['student_id'])) for a in attempts])

@app.route('/api/teacher/results/<int:attempt_id>', methods=['GET'])
@login_required('teacher')
def teacher_result_detail(attempt_id):
    attempt = db.attempts.find_one({'id': attempt_id}, {'_id': 0})
    if not attempt:
        return jsonify({'error': 'Not found'}), 404
    test = db.tests.find_one({'id': attempt['test_id'], 'teacher_id': session['user_id']})
    if not test:
        return jsonify({'error': 'Not found'}), 404
    user = db.users.find_one({'id': attempt['student_id']}) or {}
    answers = json.loads(attempt.get('answers') or '{}')
    detail = [{'id': q['id'], 'question': q['question_text'], 'options': q['options'],
               'correct_option': q['correct_option'],
               'given_option': answers.get(str(q['id'])), 'marks': q['marks']}
              for q in db.questions.find({'test_id': attempt['test_id']}).sort('id', 1)]
    attempt_out = dict(attempt)
    attempt_out.update({'title': test['title'], 'student_name': user.get('name', ''),
                        'student_email': user.get('email', '')})
    return jsonify({'attempt': attempt_out, 'questions': detail})

# ══════════════════════════════════════════════════════
# STUDENT APIs
# ══════════════════════════════════════════════════════
def is_assigned(tid):
    return db.test_assignments.find_one({'test_id': tid, 'student_email': session['email']}) is not None

@app.route('/api/student/tests', methods=['GET'])
@login_required('student')
def student_tests():
    tids = [a['test_id'] for a in db.test_assignments.find({'student_email': session['email']})]
    tests = list(db.tests.find({'id': {'$in': tids}}))
    tests.sort(key=lambda t: (t.get('start_time') is None, t.get('start_time') or ''))
    result = []
    for t in tests:
        a = db.attempts.find_one({'test_id': t['id'], 'student_id': session['user_id']}, {'_id': 0})
        attempt = None
        if a:
            attempt = {'id': a['id'], 'score': a.get('score', 0), 'total_marks': a.get('total_marks', 0),
                       'submitted_at': a.get('submitted_at'), 'started_at': a.get('started_at')}
        result.append({'id': t['id'], 'title': t['title'], 'description': t.get('description'),
                       'duration_minutes': t.get('duration_minutes'), 'start_time': t.get('start_time'),
                       'end_time': t.get('end_time'), 'attempt': attempt})
    return jsonify(result)

@app.route('/api/student/tests/<int:tid>', methods=['GET'])
@login_required('student')
def student_get_test(tid):
    if not is_assigned(tid):
        return jsonify({'error': 'Not assigned to this test'}), 403
    attempt = db.attempts.find_one({'test_id': tid, 'student_id': session['user_id']})
    if attempt and attempt.get('submitted_at'):
        return jsonify({'error': 'Already submitted', 'attempt_id': attempt['id']}), 409
    t = db.tests.find_one({'id': tid})
    if not t:
        return jsonify({'error': 'Test not found'}), 404
    questions = db.questions.find({'test_id': tid}).sort('id', 1)
    return jsonify({'id': t['id'], 'title': t['title'], 'description': t.get('description'),
                    'duration_minutes': t.get('duration_minutes'), 'start_time': t.get('start_time'),
                    'end_time': t.get('end_time'), 'attempt_id': attempt['id'] if attempt else None,
                    'questions': [{'id': q['id'], 'question': q['question_text'],
                                   'options': q['options'], 'marks': q['marks']} for q in questions]})

@app.route('/api/student/tests/<int:tid>/start', methods=['POST'])
@login_required('student')
def student_start_test(tid):
    if not is_assigned(tid):
        return jsonify({'error': 'Not assigned'}), 403
    existing = db.attempts.find_one({'test_id': tid, 'student_id': session['user_id']})
    if existing:
        if existing.get('submitted_at'):
            return jsonify({'error': 'Already submitted', 'attempt_id': existing['id']}), 409
        return jsonify({'attempt_id': existing['id']})
    aid = next_id('attempts')
    try:
        db.attempts.insert_one({'id': aid, 'test_id': tid, 'student_id': session['user_id'],
                                'answers': '{}', 'score': 0, 'total_marks': 0,
                                'started_at': now_str(), 'submitted_at': None})
    except DuplicateKeyError:   # double-click / two tabs
        existing = db.attempts.find_one({'test_id': tid, 'student_id': session['user_id']})
        return jsonify({'attempt_id': existing['id']})
    return jsonify({'attempt_id': aid})

@app.route('/api/student/attempts/<int:aid>/save', methods=['POST'])
@login_required('student')
def student_save_answers(aid):
    d = request.json
    attempt = db.attempts.find_one({'id': aid, 'student_id': session['user_id']})
    if not attempt:
        return jsonify({'error': 'Not found'}), 404
    if attempt.get('submitted_at'):
        return jsonify({'error': 'Already submitted'}), 409
    db.attempts.update_one({'id': aid}, {'$set': {'answers': json.dumps(d.get('answers', {}))}})
    return jsonify({'ok': True})

@app.route('/api/student/attempts/<int:aid>/submit', methods=['POST'])
@login_required('student')
def student_submit(aid):
    d = request.json or {}
    attempt = db.attempts.find_one({'id': aid, 'student_id': session['user_id']})
    if not attempt:
        return jsonify({'error': 'Not found'}), 404
    if attempt.get('submitted_at'):
        return jsonify({'ok': True, 'attempt_id': aid})
    answers = d.get('answers', json.loads(attempt.get('answers') or '{}'))
    score, total = 0, 0
    for q in db.questions.find({'test_id': attempt['test_id']}):
        total += q['marks']
        given = answers.get(str(q['id']))
        if given is not None and int(given) == q['correct_option']:
            score += q['marks']
    db.attempts.update_one({'id': aid, 'submitted_at': None},
                           {'$set': {'answers': json.dumps(answers), 'score': score,
                                     'total_marks': total, 'submitted_at': now_str()}})
    return jsonify({'ok': True, 'attempt_id': aid, 'score': score, 'total': total})

@app.route('/api/student/results/<int:aid>', methods=['GET'])
@login_required('student')
def student_result(aid):
    attempt = db.attempts.find_one({'id': aid, 'student_id': session['user_id']})
    if not attempt:
        return jsonify({'error': 'Not found'}), 404
    test = db.tests.find_one({'id': attempt['test_id']}) or {}
    answers = json.loads(attempt.get('answers') or '{}')
    detail = [{'id': q['id'], 'question': q['question_text'], 'options': q['options'],
               'correct_option': q['correct_option'],
               'given_option': int(answers[str(q['id'])]) if answers.get(str(q['id'])) is not None else None,
               'marks': q['marks']}
              for q in db.questions.find({'test_id': attempt['test_id']}).sort('id', 1)]
    return jsonify({'attempt': {'id': attempt['id'], 'score': attempt.get('score', 0),
                                'total_marks': attempt.get('total_marks', 0),
                                'started_at': attempt.get('started_at'),
                                'submitted_at': attempt.get('submitted_at'),
                                'title': test.get('title', ''),
                                'duration_minutes': test.get('duration_minutes'),
                                'test_id': attempt['test_id']},
                    'questions': detail})

# Connect on import so it also works under gunicorn/waitress, not just `python app.py`
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    print(f'\n  ExamPortal running at  http://localhost:{port}\n  Press Ctrl+C to stop.\n')
    app.run(debug=debug, port=port, use_reloader=False)
