import sys
import pathlib
import pytest
from mockito import when, mock, unstub
import requests
import json


src_path = pathlib.Path.cwd().parent.joinpath('features')
sys.path.insert(0, str(src_path))

from steps.crypto_test import API, RequestType, EndpointType, compare_timestamps, check_id_correct

hostname = 'test.dummy'
api = API(hostname, '', "kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==", '')


def test_get_signature():
    api_sign = api._get_signature("/0/private/AddOrder", {
        "nonce": "1616492376594",
        "ordertype": "limit",
        "pair": "XBTUSD",
        "price": 37500,
        "type": "buy",
        "volume": 1.25
    })
    assert api_sign == '4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ=='


def test_compare_timestamps():
    assert compare_timestamps(1616336594, 'Sun, 21 Mar 21 14:23:14 +0000')


def test_check_id_correct():
    assert check_id_correct('ORSHSU-KI4EY-UXKLIB')


def test_api_call_get_simple():
    response_text = '{"error":[],"result":{"unixtime":1645606144,"rfc1123":"Wed, 23 Feb 22 08:49:04 +0000"}}'
    response = mock({
        'status_code': 200,
        'text': response_text,
        'json': lambda: json.loads(response_text)
    })

    when(requests).get(f'https://{hostname}/0/public/Time', headers=None, params=None).thenReturn(response)

    assert api.call(RequestType.GET, EndpointType.PUBLIC, 'Time') == {
        "error": [ ],
        "result":
        {
            "unixtime": 1645606144,
            "rfc1123": "Wed, 23 Feb 22 08:49:04 +0000"
        }
    }


def test_api_call_get_simple_exception():
    # json string in erroneous format - abundant curly bracket at the end
    response_text = '{"error":[],"result":{"unixtime":1645606144,"rfc1123":"Wed, 23 Feb 22 08:49:04 +0000"}}}'

    response = requests.models.Response()
    response.status_code = 200
    response._content = response_text.encode()

    when(requests).get(f'https://{hostname}/0/public/Time', headers=None, params=None).thenReturn(response)

    with pytest.raises(API.APIError) as exc_info:
        api.call(RequestType.GET, EndpointType.PUBLIC, 'Time')

    assert exc_info.type == API.APIError
    assert exc_info.match(r'^Executing request GET https://test.dummy/0/public/Time: ERROR: Extra data:')
