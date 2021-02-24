# -*- coding: UTF-8 -*-

from insights.client.apps.ansible.playbook_verifier import verify, PlaybookVerificationError
from insights.client.apps.ansible.playbook_verifier.contrib import oyaml as yaml
from insights.client.apps.ansible.playbook_verifier.contrib import gnupg
from collections import OrderedDict
from mock.mock import patch, Mock, mock_open
from pytest import raises
import os
import six


def test_skip_validation():
    result = verify([{'name': "test playbook"}], skipVerify=True, checkVersion=False)
    assert result == [{'name': "test playbook"}]


def test_egg_validation_error():
    egg_error = 'EGG VERSION ERROR: Current running egg is not the most recent version'
    fake_playbook = [{'name': "test playbook"}]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook)
    assert egg_error in str(error.value)


def test_vars_not_found_error():
    vars_error = 'VARS FIELD NOT FOUND: Verification failed'
    fake_playbook = [{'name': "test playbook"}]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook, checkVersion=False)
    assert vars_error in str(error.value)


def test_signature_not_found_error():
    sig_error = 'SIGNATURE NOT FOUND: Verification failed'
    fake_playbook = [{'name': "test playbook", 'vars': {}}]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook, checkVersion=False)
    assert sig_error in str(error.value)


@patch('insights.client.apps.ansible.playbook_verifier.PUBLIC_KEY_FOLDER', './testing')
def test_key_not_imported():
    key_error = "PUBLIC KEY NOT IMPORTED: Public key import failed"
    fake_playbook = [{
        'name': "test playbook",
        'vars': {
            'insights_signature': 'TFMwdExTMUNSVWRKVGlCUVIxQWdVMGxIVGtGVVZWSkZMUzB0TFMwS0N==',
            'insights_signature_exclude': '/vars/insights_signature'
        }
    }]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook, checkVersion=False)
    assert key_error in str(error.value)


@patch('insights.client.apps.ansible.playbook_verifier.PUBLIC_KEY_FOLDER', None)
def test_key_import_error():
    key_error = "PUBLIC KEY IMPORT ERROR: Public key file not found"
    fake_playbook = [{
        'name': "test playbook",
        'vars': {
            'insights_signature': 'TFMwdExTMUNSVWRKVGlCUVIxQWdVMGxIVGtGVVZWSkZMUzB0TFMwS0N==',
            'insights_signature_exclude': '/vars/insights_signature'
        }
    }]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook, checkVersion=False)
    assert key_error in str(error.value)


@patch('insights.client.apps.ansible.playbook_verifier.verifyPlaybookSnippet', return_value=[])
def test_playbook_verification_error(call):
    key_error = 'SIGNATURE NOT VALID: Template [name: test playbook] has invalid signature'
    fake_playbook = [{
        'name': "test playbook",
        'vars': {
            'insights_signature': 'TFMwdExTMUNSVWRKVGlCUVIxQWdVMGxIVGtGVVZWSkZMUzB0TFMwS0N==',
            'insights_signature_exclude': '/vars/insights_signature'
        }
    }]

    with raises(PlaybookVerificationError) as error:
        verify(fake_playbook, checkVersion=False)
    assert key_error in str(error.value)


@patch('gnupg.GPG.verify_data', return_value=True)
def test_playbook_verification_success(call):
    with open('insights/client/apps/ansible/test_playbook.yml', 'r') as test_file:
        fake_playbook = yaml.load(test_file, Loader=yaml.FullLoader)

    result = verify(fake_playbook, checkVersion=False)
    assert result == fake_playbook
