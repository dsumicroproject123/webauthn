from flask import Flask, render_template, request, jsonify, session
from py_webauthn.server import RelyingParty
from py_webauthn.server import PublicKeyCredentialRpEntity
from py_webauthn.server import PublicKeyCredentialUserEntity
from py_webauthn.server import generate_challenge
from py_webauthn.server import validate_credential_request
from py_webauthn.server import validate_assertion
from flask_sqlalchemy import SQLAlchemy
import base64

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

rp = RelyingParty(
    'WebAuthn Registration and Login',
    'http://127.0.0.1:5000/',  # Update with your app's URL
    'http://127.0.0.1:5000/'  # Update with your app's ID
)
app.config['SQLALCHENY_DATABASE_URI'] ="sqlite:///User.db"
app.config['SQLALCHENY_TTACH_MODIFICATION'] = False
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(200), nullable=False)  # User's WebAuthn ID
    credential_id = db.Column(db.String(200), nullable=False)  # User's WebAuthn Credential ID
    public_key_credential = db.Column(db.String(200), nullable=False)  # User's WebAuthn Public Key

    def __init__(self, username, display_name, user_id, credential_id, public_key_credential):
        self.username = username
        self.display_name = display_name
        self.user_id = user_id
        self.credential_id = credential_id
        self.public_key_credential = public_key_credential


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        display_name = request.form.get('display_name')

        # Generate a new user ID and credential ID (these should be securely generated)
        user_id = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')
        credential_id = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')

        user = User(username=username, display_name=display_name, user_id=user_id, credential_id=credential_id)
        db.session.add(user)
        db.session.commit()

        challenge = generate_challenge(32)
        session['challenge'] = challenge
        user_entity = PublicKeyCredentialUserEntity(user_id, display_name)
        rp_entity = PublicKeyCredentialRpEntity(rp.name, rp.id)

        credential_options, session_data = rp.begin_registration(
            user_entity,
            credential_id,
            challenge
        )

        session['registration_session_data'] = session_data
        return jsonify(credential_options)

    return render_template('register.html')

@app.route('/verify_registration', methods=['POST'])
def verify_registration():
    response = request.get_json()
    credential_data = response['credential']
    client_data = response['clientDataJSON']

    session_data = session.pop('registration_session_data')

    try:
        registration_response = validate_credential_request(
            credential_data,
            client_data,
            session_data,
            rp.trust_anchor_dir
        )
        rp.register(
            registration_response,
            session_data['publicKey']
        )
        return jsonify({'message': 'Registration successful!'})
    except Exception as e:
        return jsonify({'message': f'Registration failed: {str(e)}'}), 400

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('login_username')
        user = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({'message': 'Login failed. User not found.'}), 400

        challenge = generate_challenge(32)
        session['challenge'] = challenge

        credential_options, session_data = rp.begin_assertion(
            user.user_id,
            challenge
        )

        session['assertion_session_data'] = session_data
        return jsonify(credential_options)

    return render_template('login.html')

@app.route('/verify_login', methods=['POST'])
def verify_login():
    response = request.get_json()
    credential_data = response['credential']
    client_data = response['clientDataJSON']

    session_data = session.pop('assertion_session_data')

    try:
        assertion_response = validate_assertion(
            credential_data,
            client_data,
            session_data,
            user.public_key_credential
        )
        return jsonify({'message': 'Login successful!'})
    except Exception as e:
        return jsonify({'message': f'Login failed: {str(e)}'}), 400

if __name__ == '__main__':
    app.run(debug=True)
