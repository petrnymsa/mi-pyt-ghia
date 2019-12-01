import betamax
import os
import pytest
from ghia.assigner import GitHubIssueAssigner

api_token = os.environ.get('GITHUB_TOKEN', 'fizztoken')
api_repo = os.environ.get('GITHUB_REPO', 'repotest')


with betamax.Betamax.configure() as config:
    config.cassette_library_dir = 'tests/fixtures/cassettes'
    # config.default_cassette_options['serialize_with'] = 'prettyjson'
    config.define_cassette_placeholder('<AUTH_TOKEN>', api_token)

@pytest.fixture
def client(betamax_session):
    return GitHubIssueAssigner(api_token, api_repo,betamax_session)

@pytest.fixture
def fake_client(betamax_session):
    return GitHubIssueAssigner('faketoken', 'fakerepo', betamax_session)

