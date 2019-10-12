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

    return r['name']


def verify_signature(payload, recieved_signature):
    signature = hmac.new(b'ghia', payload, hashlib.sha1).hexdigest()
    return hmac.compare_digest(signature, recieved_signature.split('=')[1])


def process_post(req):
    if not verify_signature(req.data, req.headers['X-Hub-Signature']):
        return flask.jsonify({'message': 'Not valid X-Hub-Signature'}), 401

    data = json.loads(req.data)
    allowed_actions = ['opened', 'edited', 'transferred',
                       'reopened', 'assigned', 'unassigned', 'labeled', 'unlabeled']

    if not data['action'] in allowed_actions or data['issue']['state'] == 'closed':
        print(
            f"Issue {data['issue']['title']} not processed due to action {data['action']} not allowed or is closed")
        return '', 201

    return '', 201


def create_app(config=None):
    app = flask.Flask(__name__)
    app.logger.info('App initialized')

    cfg = os.environ.get('GHIA_CONFIG')
    cfg_files = cfg.split(':')
    for f in cfg_files:
        pass

    @app.route('/', methods=['GET', 'POST'])
    def index():
        # init()

        if flask.request.method == 'POST':
            return process_post(flask.request)
        else:
            return flask.render_template('index.html', data=[])

    return app


if __name__ == '__main__':
    cli.run()
