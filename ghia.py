import configparser
import os.path
import os
import click
import re
import json
import flask
import hashlib
import hmac
import requests
# --------------------------------------------------------------
from issue import Issue, IssueChange
from rule import Rule, RuleSet
from assigner import GitHubIssueAssigner
import configreader
import cli
# --------------------------------------------------------------


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


# def issue_from_json(text):
#     labels = list(map(lambda x: x['name'], text['labels']))
#     assignees = list(
#         map(lambda x: x['login'], text['assignees']))
#     return Issue(
#         text['number'], text['html_url'], text['title'], text['body'], labels, assignees)


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
    repo = data['repository']['full_name']
    gh = GitHubIssueAssigner(auth[0], repo, 'append')
    gh.issues = [Issue.from_json(issue_json)]
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
    try:
        return configreader.read_auth(file)
    except:
        return None


def try_get_rules(file):
    try:
        return configreader.read_rules(file)
    except:
        return None


def create_app(config=None):
    app = flask.Flask(__name__)
    app.logger.info('App initialized')

    cfg = os.environ.get('GHIA_CONFIG')
    cfg_files = cfg.split(':')

    rules = []
    for f in cfg_files:
        auth = try_get_auth(f)
        if auth:
            app.config['auth'] = auth

        r = try_get_rules(f)
        if r:
            rules += r[0]
            if r[1]:  # todo what about multiple fallbacks?
                app.config['fallback'] = r[1]

    app.config['rules'] = rules

    app.config['user'] = get_username(app.config['auth'][0])

    @app.route('/', methods=['GET', 'POST'])
    def index():
        # init()
        if flask.request.method == 'POST':
            ev = flask.request.headers['X-GitHub-Event']

            if ev == 'ping':
                return process_ping(flask.request)

            return process_issue_post(flask.request)
        else:
            rules = flask.current_app.config['rules']
            user = flask.current_app.config['user']
            return flask.render_template('index.html', rules=rules, user=user)

    return app


if __name__ == '__main__':
    cli.run()
