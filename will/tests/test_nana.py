import pytest
import mock
import json
from will.plugins.nana_tools.nana import NanaPlugin


@pytest.fixture
def nana():
    nana = NanaPlugin()
    return nana


@pytest.fixture
def load_test_data():

    def _load(name):
        with open('files/splunk_alert_%s.json' % name) as f:
            return json.loads(f.read())
    return _load

@pytest.fixture
def set_response(load_test_data):

    def _set(name):
        data = load_test_data(name)
        with mock.patch('requests.Session') as Session:
            Session.return_value = sess = mock.MagicMock()
            sess.get.return_value = response = mock.MagicMock()
            response.json.return_value = data


def test_splunk_alert(nana, load_test_data):
    nana.request = mock.MagicMock()
    nana.request.json = {
        'sid': 'scheduler__admin_YXRsYXNzaWFuLWFwcC1zZWNpbnQ__RMD50c8edda995b82e19_at_1463032920_7'
    }

    with mock.patch('requests.Session') as Session:
        Session.return_value = sess = mock.MagicMock()
        sess.get.return_value = response = mock.MagicMock()

        response.json.return_value = load_test_data('empty_results')
        nana._create_question = mock.MagicMock()
        nana.splunk_alert()
        assert nana._create_question.call_count == 0

        response.json.return_value = load_test_data('success')
        nana._create_question = mock.MagicMock()
        nana.splunk_alert()
        assert nana._create_question.call_count == 1
        (q, ), _ = nana._create_question.call_args
        expected = {
            "targetName": "foobar",
            "question": "Waddup?",
            "targetEmail": "a@b",
            "targetUID": "123",
            "targetID": "asd"
        }
        assert q == expected

        response.json.return_value = load_test_data('invalid_sid')
        nana._create_question = mock.MagicMock()
        with pytest.raises(ValueError):
            nana.splunk_alert()
        assert nana._create_question.call_count == 0


@pytest.mark.xfail
def test__create_question(nana):
    assert 0


def test_validate_question(nana):
    question = {}
    ret, q, comm = nana.validate_question(question)
    assert ret is False
    assert 'No identifiable question' in comm

    question['question'] = 'Foo'
    ret, q, comm = nana.validate_question(question)
    assert ret is False
    assert 'No identifiable targets' in comm

    question['targetUID'] = '123'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert comm == ''

    del question['targetUID']
    question['targetName'] = '123'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert comm == ''

    del question['targetName']
    question['targetEmail'] = '123'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert comm == ''

    del question['targetEmail']
    question['targetID'] = '123'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert comm == ''

    question['severity'] = '6'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['severity'] == '3'

    question['severity'] = '4'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['severity'] == '4'

    question['multipleChoice'] = None
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['multipleChoice'] is False

    question['multipleChoice'] = True
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['multipleChoice'] is True

    question['answers'] = None
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['answers'] == {"yes": True, "no": False}

    question['answers'] = {'yo': True, 'nope': False}
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['answers'] == {'yo': True, 'nope': False}

    question['format'] = 'asd'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['format'] == 'text'

    question['format'] = 'HTML'
    ret, q, comm = nana.validate_question(question)
    assert ret is True
    assert q['format'] == 'HTML'
