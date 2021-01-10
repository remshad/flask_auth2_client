import ssl

from flask import Flask


from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

github = oauth.remote_app(
    'github',
    consumer_key='PoKCrD07e9qXmeDGeUPRdLIM',
    consumer_secret='QBRs1D3u7AWIDKRQYb2YE6BRQ7mwIqZ82X01q7W2xpJ0SBkt',
    request_token_params={'scope': 'profile'},
    base_url='https://127.0.0.1:7000/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://127.0.0.1:5000/oauth/token',
    authorize_url='https://127.0.0.1:5000/oauth/authorize'
)


@app.route('/')
def index():
    if 'github_token' in session:
        me = github.get('user')
        return jsonify(me.data)
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('github_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    session['github_¸token'] = (resp['access_token'], '')
    me = github.get('user')
    return jsonify(me.data)


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

#
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
# context.verify_mode = ssl.CERT_REQUIRED
# context.load_verify_locations("localhost.crt")
# context.load_cert_chain("localhost.crt", "localhost.key")

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=int("7000"),ssl_context='adhoc')