import sys
import os
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from enum import Enum, auto
import logging
import re
from json.decoder import JSONDecodeError
import pyotp

import urllib.parse
import hashlib
import hmac
import base64

import requests
from behave import *


logging.basicConfig(
    filename='logs/crypto_test.log',
    filemode='a',
    format='%(asctime)s,%(msecs)d  %(levelname)-10s%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG)

log = logging.getLogger('crypto_test')
log.setLevel(logging.DEBUG)


class RequestType(Enum):
    GET = 'get'
    POST = 'post'


class EndpointType(Enum):
    PUBLIC = '/0/public/'
    PRIVATE = '/0/private/'


class API:
    class APIError(Exception):
        pass

    instances = {}

    @classmethod
    def get_keys(cls):
        env = os.environ
        if not (api_key := env.get('API_KEY_KRAKEN')):
            msg = 'API_KEY_KRAKEN env variable not set'
            log.error(msg)
            raise cls.APIError(msg)

        if not (api_sec := env.get('API_SEC_KRAKEN')):
            msg = 'API_SEC_KRAKEN env variable not set'
            log.error(msg)
            raise cls.APIError(msg)

        if not (totp_sec := env.get('TOTP_SEC_KRAKEN')):
            msg = 'TOTP_SEC_KRAKEN env variable not set'
            log.error(msg)
            raise cls.APIError(msg)

        return api_key, api_sec, totp_sec

    @classmethod
    def get_instance(cls, hostname):
        if hostname not in cls.instances:
            cls.instances[hostname] = cls(hostname, *cls.get_keys())
        return cls.instances[hostname]

    def __init__(self, hostname, api_key, api_sec, totp_sec):
        self._origin = f'https://{hostname}'
        self._api_sec = api_sec
        self._totp = pyotp.TOTP(totp_sec)
        self._headers = {'API-Key': api_key}

    @staticmethod
    def _gen_nonce():
        return str(int(time.time() * 1000))

    def _get_signature(self, urlpath, data):
        postdata = urllib.parse.urlencode(data)
        encoded = (str(data['nonce']) + postdata).encode()
        message = urlpath.encode() + hashlib.sha256(encoded).digest()

        try:
            mac = hmac.new(base64.b64decode(self._api_sec), message, hashlib.sha512)
        except Exception:
            msg = 'Signature creation Error: API secret in incorrect format'
            log.error(msg)
            raise self.APIError(msg)

        sigdigest = base64.b64encode(mac.digest())
        return sigdigest.decode()

    @staticmethod
    def _get(url, headers, data):
        r = requests.get(url, headers=headers, params=data)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _post(url, headers, data):
        r = requests.post(url, headers=headers, data=data)
        r.raise_for_status()
        return r.json()

    def call(self, request_type, endpoint_type, endpoint_name, data=None):
        urlpath = endpoint_type.value + endpoint_name
        url = self._origin + urlpath

        if request_type == RequestType.POST:
            assert data, 'No data provided'
            try:
                data_prefix = {
                    'nonce': self._gen_nonce(),
                    'otp': self._totp.now(),
                } if endpoint_type == EndpointType.PRIVATE else {}
            except Exception:
                msg = 'OTP creation Error: TOTP secret in incorrect format'
                log.error(msg)
                raise self.APIError(msg)

            data = {
                **data_prefix,
                **data
            }

        headers = {
            **self._headers,
            'API-Sign': self._get_signature(urlpath, data)
        } if endpoint_type == EndpointType.PRIVATE else None

        request_handler = getattr(self, '_' + request_type.value)
        log_msg = f'Executing request {request_type.name} {url}'
        try:
            log.debug(f'{log_msg}: HEADERS: {headers} DATA: {data}')
            response = request_handler(url, headers, data)
        except (requests.exceptions.RequestException, JSONDecodeError) as e:
            msg = f'{log_msg}: ERROR: {str(e)}'
            log.error(msg)
            raise self.APIError(msg)

        log.debug(f'{log_msg}: Response: ERROR: {response["error"]} RESULT: {response.get("result")}')
        log.info(f'{log_msg}: SUCCESS')
        return response


def parse_request_params(request_type, endpoint_type, endpoint, data=None):
    data = ' ' + str(data) if data else ''
    return f'{endpoint_type.name} {request_type.name} {endpoint}{data}'


def check_response_fields(result, request_str, fields):
    for field in fields:
        name, _type = field
        assert name in result, f"Missing field '{name}' in result for {request_str}"
        value = result[name]
        if _type is not None:
            assert isinstance(value, _type), (f"Incorrect type for field '{name}' in result for {request_str}"
                                              f" (expected {_type} - got {type(value)})")


def compare_timestamps(unixtime, rfc1123):
    return datetime.fromtimestamp(unixtime).timestamp() == parsedate_to_datetime(rfc1123).timestamp()


def check_id_correct(_id):
    return bool(re.match(r'^[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{6}$', _id))


class ValidationError(Exception):
    pass


@given('an API access to "{hostname}"')
def step_impl(context, hostname):
    context.table_data = context.table
    context.api = API.get_instance(hostname)


@when('we get server time')
def step_impl(context):
    request_params = RequestType.GET, EndpointType.PUBLIC, 'Time'
    context.request_str = parse_request_params(*request_params)
    context.response = context.api.call(*request_params)


@when('we get tradable asset pairs for "{pairs}"')
def step_impl(context, pairs):
    context.table_data = {row['name']: row['altname'] for row in context.table_data}
    context.pairs = pairs.split(',')

    request_params = RequestType.GET, EndpointType.PUBLIC, 'AssetPairs', {'pair': pairs}
    context.request_str = parse_request_params(*request_params)
    context.response = context.api.call(*request_params)


@when('we get open orders')
def step_impl(context):
    request_params = RequestType.POST, EndpointType.PRIVATE, 'OpenOrders', {'trades': True}
    context.request_str = parse_request_params(*request_params)
    context.response = context.api.call(*request_params)


@then('successful response is received')
def step_impl(context):
    response = context.response
    error = response['error']
    assert "result" in response, f'Request failed or rejected: {error}'
    if len(error):
        log.warning(f'Got warning while receiving response for {context.request_str}: {error}')


@then('get server time response is validated OK')
def step_impl(context):
    request_str = context.request_str
    result = context.response['result']
    check_response_fields(result, request_str, (
        ('unixtime', int),
        ('rfc1123', str)
    ))
    assert compare_timestamps(result['unixtime'], result['rfc1123']),\
        f'Timestamp fields do not match in result for {request_str}'


@then('get tradable asset pairs response is validated OK')
def step_impl(context):
    table_data = context.table_data
    request_str = context.request_str
    result = context.response['result']
    for pair in context.pairs:
        request_pair_str = request_str + f" in pair {pair}"
        assert pair in result, f"Pair '{pair}' not present in result for {request_str}"
        pair_result = result[pair]
        check_response_fields(pair_result, request_pair_str, (
            ("altname", str),
            ("wsname", str),
            ("aclass_base", str),
            ("base", str),
            ("aclass_quote", str),
            ("quote", str),
            ("lot", str),
            ("pair_decimals", int),
            ("lot_decimals", int),
            ("lot_multiplier", int),
            ("leverage_buy", list),
            ("leverage_sell", list),
            ("fees", list),
            ("fees_maker", list),
            ("fee_volume_currency", str),
            ("margin_call", int),
            ("margin_stop", int),
            ("ordermin", str)
        ))
        assert table_data[pair] == pair_result['altname'], (f"Incorrect altname in result for {request_pair_str}"
                                                    f" (expected {table_data[pair]} - got {pair_result['altname']})")


@then('get open orders response is validated OK')
def step_impl(context):
    request_str = context.request_str
    result = context.response['result']
    assert 'open' in result, f"Field 'open' not present in result for {request_str}"
    for k, v in result['open'].items():
        assert check_id_correct(k), f"Order ID '{k}' has incorrect format in result for {request_str}"
        request_order_str = request_str + f" in order {k}"
        check_response_fields(v, request_order_str, (
            ("refid", None),
            ("userref", int),
            ("status", str),
            ("opentm", float),
            ("starttm", int),
            ("expiretm", int),
            ("descr", dict),
            ("vol", str),
            ("vol_exec", str),
            ("cost", str),
            ("fee", str),
            ("price", str),
            ("stopprice", str),
            ("limitprice", str),
            ("misc", str),
            ("oflags", str)
        ))
        assert v['status'] == 'open', f"Field 'status' is not set to 'open' in result for {request_order_str}"
        check_response_fields(v['descr'], request_order_str + " inside 'descr'", (
            ("pair", str),
            ("type", str),
            ("ordertype", str),
            ("price", str),
            ("price2", str),
            ("leverage", str),
            ("order", str),
            ("close", str)
        ))
        if 'trades' in v:
            for _id in v['trades']:
                assert check_id_correct(_id), f"Trade ID '{_id}' has incorrect format in result for {request_order_str}"
