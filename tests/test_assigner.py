import betamax

with betamax.Betamax.configure() as config:
    # tell Betamax where to find the cassettes
    # make sure to create the directory
    config.cassette_library_dir = 'tests/fixtures/cassettes'


def test_get(betamax_session):
    betamax_session.get('https://www.seznam.cz')
