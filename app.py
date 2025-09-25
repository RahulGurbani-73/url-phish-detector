from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify
import validators, tldextract, socket, io, csv, qrcode, whois
from urllib.parse import urlparse
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET','dev-key')

BLACKLIST = {'phishy.example', 'malicious.org', 'badsite.net'}
SUSPICIOUS_WORDS = ['login','secure','update','verify','account','bank','confirm','signin','paypal','appleid','webscr']

def is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except:
        return False

def domain_age_days(domain):
    try:
        w = whois.whois(domain)
        d = w.creation_date
        if isinstance(d, list):
            d = d[0]
        if not d:
            return None
        return (datetime.now() - d).days
    except Exception:
        return None

def score_url(url):
    reasons = []
    score = 0
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    if not validators.url(url):
        reasons.append('invalid_url_format')
        score += 50
        return {'url':url,'score':score,'label':'Invalid','reasons':reasons}
    parsed = urlparse(url)
    host = parsed.netloc.split('@')[-1]
    ext = tldextract.extract(host)
    domain = '.'.join(p for p in (ext.domain, ext.suffix) if p)

    if is_ip(host):
        reasons.append('ip_address_in_host')
        score += 20
    if '@' in url:
        reasons.append('at_symbol_in_url')
        score += 20
    if len(url) > 75:
        reasons.append('long_url')
        score += 8
    if any(w in url.lower() for w in SUSPICIOUS_WORDS):
        reasons.append('suspicious_keyword')
        score += 12
    if '-' in (ext.domain or ''):
        reasons.append('hyphen_in_domain')
        score += 5
    if host.count('.')>=3:
        reasons.append('many_subdomains')
        score += 6
    if any(b in host.lower() for b in BLACKLIST):
        reasons.append('blacklisted_domain')
        score += 45
    age = domain_age_days(domain)
    if age is None:
        reasons.append('whois_unavailable')
        score += 3
    else:
        if age < 90:
            reasons.append('recent_domain (<90d)')
            score += 12
        elif age < 365:
            reasons.append('new_domain (<1yr)')
            score += 6
    if parsed.scheme != 'https':
        reasons.append('no_https')
        score += 4
    label = 'Likely Safe'
    if score >= 40:
        label = 'Likely Phishing'
    elif score >= 20:
        label = 'Suspicious'
    return {'url':url,'score':score,'label':label,'reasons':reasons,'age_days':age}

@app.route('/', methods=['GET','POST'])
def index():
    result = None
    if request.method == 'GET' and request.args.get('u'):
        result = score_url(request.args.get('u'))
    if request.method == 'POST':
        url = request.form.get('url','').strip()
        result = score_url(url)
    return render_template('index.html', result=result)

@app.route('/share', methods=['POST'])
def share():
    url = request.form.get('url','')
    r = score_url(url)
    return jsonify(r)

@app.route('/qrcode')
def qrcode_route():
    url = request.args.get('url','')
    if not url:
        return 'No url', 400
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/bulk', methods=['POST'])
def bulk():
    f = request.files.get('csvfile')
    if not f:
        flash('No file uploaded','warning')
        return redirect(url_for('index'))
    data = io.StringIO(f.stream.read().decode('utf-8'), newline=None)
    reader = csv.reader(data)
    results = []
    for row in reader:
        if row:
            results.append(score_url(row[0]))
    # counts summary
    summary = {'Likely Safe':0,'Suspicious':0,'Likely Phishing':0,'Invalid':0}
    for r in results:
        summary[r['label']] = summary.get(r['label'],0) + 1
    return render_template('bulk.html', results=results, summary=summary)

@app.route('/export', methods=['POST'])
def export():
    urls = request.form.getlist('urls')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['url','score','label','reasons'])
    for u in urls:
        r = score_url(u)
        writer.writerow([r['url'], r['score'], ';'.join(r['reasons'])])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name='results.csv')

if __name__ == '__main__':
    app.run(debug=True)
