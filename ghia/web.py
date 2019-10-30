import flask
import requests
import json
import hmac
import os
import hashlib
from .issue import Issue, IssueChange
from .assigner import GitHubIssueAssigner
import ghia.configreader as configreader


def get_username(token):
    headers = {'Authorization': 'token ' + token}
    r = requests.get('https://api.github.com/user', headers=headers)
    r.raise_for_status()

    data = json.loads(r.text)
    return data['login']


def verify_signature(secret, payload, recieved_signature):
    signature = hmac.new(str.encode(secret),
                         payload, hashlib.sha1).hexdigest()
    return hmac.compare_digest(signature, recieved_signature.split('=')[1])


def process_issue_post(req):
    auth = flask.current_app.config['auth']
    if 'X-Hub-Signature' not in req.headers or not verify_signature(auth[1], req.data, req.headers['X-Hub-Signature']):
        return flask.jsonify({'message': 'Not valid X-Hub-Signature'}), 401

    data = json.loads(req.data)
    allowed_actions = ['opened', 'edited', 'transferred',
                       'reopened', 'assigned', 'unassigned', 'labeled', 'unlabeled']

    if not data['action'] in allowed_actions or data['issue']['state'] == 'closed':
        print(
            f"Issue {data['issue']['title']} not processed due to action {data['action']} not allowed or is closed")
        return '', 201

    issue_json = data['issue']
    issue = Issue.from_json(issue_json)
    repo = data['repository']['full_name']
    flask.current_app.config['issues'].append((issue, data['action']))

    gh = GitHubIssueAssigner(auth[0], repo, 'append')
    gh.issues = [issue]
    gh.proces_issues(
        flask.current_app.config['rules'], flask.current_app.config['fallback'], False)
    return '', 201


def process_ping(req):
    secret = flask.current_app.config['auth'][1]
    if 'X-Hub-Signature' not in req.headers:
        return '', 200
    elif not verify_signature(secret, req.data, req.headers['X-Hub-Signature']):
        return flask.jsonify({'message': 'Not valid X-Hub-Signature'}), 401
    else:
        return '', 200


def try_get_auth(file):
   # try:
    return configreader.read_auth(file)
   # except:
    #    return None


def try_get_rules(file):
    try:
        return configreader.read_rules(file)
    except:
        return None


def create_app(config=None):
    app = flask.Flask(__name__)
    app.logger.info('App initialized')

    cfg = os.environ.get('GHIA_CONFIG')
    app.logger.info(cfg)
    cfg_files = cfg.split(';')

    rules = []
    app.config['fallback'] = None
    app.config['auth'] = None
    for f in cfg_files:
        app.logger.info(f'Reading {f}')
        auth = try_get_auth(f)
        if auth:
            app.logger.info(f'Auth is {auth}')
            app.config['auth'] = auth
        else:
            app.logger.info(f'No auth')
        r = try_get_rules(f)
        if r:
            rules += r[0]
            if r[1]:  # todo what about multiple fallbacks?
                app.config['fallback'] = r[1]

    app.config['rules'] = rules
    app.config['issues'] = []
    app.config['user'] = get_username(app.config['auth'][0])

    @app.route('/', methods=['GET', 'POST'])
    def index():
            # init()
        if flask.request.method == 'POST':
            ev = flask.request.headers['X-GitHub-Event']

            if ev == 'ping':
                return process_ping(flask.request)
            elif ev == 'issues':
                return process_issue_post(flask.request)

            return 'Not supported event', 400
        else:
            rules = flask.current_app.config['rules']
            issues = flask.current_app.config['issues']
            user = flask.current_app.config['user']
            fallback = flask.current_app.config['fallback']
            return flask.render_template('index.html', rules=rules, user=user, issues=issues, fallback=fallback)

    return app
