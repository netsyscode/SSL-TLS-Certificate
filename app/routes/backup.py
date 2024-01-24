
@app.route('/')
def index():
    return render_template('certificate.html')

@app.route('/certificate')
def certificate_page():
    return render_template('certificate.html')

@app.route('/ca')
def ca_page():
    return render_template('ca.html')

@app.route('/get_certificate', methods=['POST'])
def get_certificate():
    domain = request.json['domain']
    result = certificates.get(domain)
    if result is None:
        result = {"content": "No certificate found for domain: " + domain, "verified": False}
    else:
        result['content'] = result['content'].replace('\n', '<br>')
    return jsonify(result)

@app.route('/get_ca', methods=['POST'])
def get_ca():
    domain = request.json['domain']
    result = cas.get(domain)
    if result is None:
        result = "No CA found for domain: " + domain
    else:
        result = result.replace('\n', '<br>')
    return jsonify(result)