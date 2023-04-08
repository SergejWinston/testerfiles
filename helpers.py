import cv2
import enum
import os
from json import JSONDecoder
from requests.adapters import HTTPAdapter

from urllib3 import Retry

import hashlib
import io
import json
import pathlib
import random
import re
import string
import sys
import threading
import time
import traceback
import typing
import vk_api
from datetime import datetime

import colorama
import lxml.html
import requests
import vk_captcha
from urllib3.exceptions import ProtocolError

from config import PROXIES_TYPE

colorama.init()
ids = []
vk_captcha.solver.logging_lock = lock = threading.Lock()
p = pathlib.Path(__file__).parent
ACCOUNTS_FILE = str(p / "config/accounts.txt")
PROXIES_FILE = str(p / "config/proxies.txt")
proxies = [i.replace('\n', '') for i in open(PROXIES_FILE, encoding='utf-8') if i.replace('\n', '')]
captcha_solver = vk_captcha.VkCaptchaSolver(True)
accounts: 'list[Account]' = []
log_events: "list[function[str]]" = []
auth_stop_event = threading.Event()


def extract_json_objects(text, decoder=JSONDecoder(), thing_to_find='['):
    pos = 0
    while True:
        match = text.find(thing_to_find, pos)
        if match == -1:
            break
        try:
            result, index = decoder.raw_decode(text[match:])
            yield result
            pos = match + index
        except ValueError:
            pos = match + 1


class CaptchaError(Exception):
    def __init__(self, sid, url):
        self.url = url
        self.sid = sid
class BannedException(PermissionError):
    def __init__(self, *args, is_spamblock=False, reason="", token=None):
        self.spamblock = is_spamblock
        self.reason = reason
        self.token = token
        super().__init__(*args)
class FA2NededEx(Exception): ...
class ConfigError(Exception): ...
class VkApiException(Exception):
    def __init__(self, error_ans: dict, *args, error_code=None):
        super().__init__(*args)
        self.error = error_ans
        error = error_ans.get("error", {})
        if isinstance(error, str):
            self.error_code = error_code or 0
            self.message = error
        else:
            self.error_code = error_code or error_ans.get("error", {}).get("error_code", 0)
            self.message = error_ans.get("error_code") or error_ans.get('error', {}).get("error_msg", "Undefined")

    def __str__(self):
        return f"VkApiException(code={self.error_code}, message=\"{self.message}\")"
class FloodControlException(requests.exceptions.ProxyError):
    pass
class AuthType(enum.Enum):
    Android = "android"
    Pc = 'pc'
    Token = 'token'
    Qr = 'qr'


def create_password():
    alphabet = string.ascii_letters+string.digits+"!@#$%^&*-+="
    return "".join(random.choice(alphabet) for _ in range(random.randint(8, 16)))


class VkTokenApi(object):

    @staticmethod
    def _get_auth_params(login, password, captcha_key, captcha_sid):
        ans = {
            'grant_type': 'password',
            'scope': 'nohttps,audio',
            'client_id': 2274003,
            'client_secret': 'hHbZxrka2uZ6jB1inYsH',
            'validate_token': 'true',
            'username': login,
            'password': password,
        }
        if captcha_key is not None: ans['captcha_key'] = captcha_key
        if captcha_sid is not None: ans['captcha_sid'] = captcha_sid
        return ans

    def __init__(self,  v=5.189, session=None, ):
        self._requests_time_lock = threading.Semaphore(3)
        self.last_method = 0
        if not session: session = requests.Session()
        self.secret = None
        random_thing = "".join(random.choice('MB12TRERTOI6.') for i in range(6))
        session.headers = {
            "User-Agent": f"VKAndroidApp/7.36-13546 (Android 11; SDK 30; arm64-v8a; Xiaomi {random_thing}; ru; 2400x1080)",
            "Accept": "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
        }
        self.session = session
        self.v = v
        # Генерируем рандомный device_id
        self.device_id = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        self.token = None
        self.user = {}
        self.user_id = None
        self.login = None
        self.password = None
    def auth(self, login=None, password=None, token=None, secret=None, auth_type: AuthType = AuthType.Token, enable_group_auth=True, change_password=False):
        self.login = login
        self.password = password
        if (token is not None and auth_type == AuthType.Token) or not password:
            self.token = token
            self.secret = secret
        elif auth_type == AuthType.Android:
            self._android_auth(login, password)
        elif auth_type == AuthType.Qr:
            self._auth_qr(login, password, token)
        else:
            try:
                self._pc_auth(login, password)
            except BannedException as e:
                if e.token: self.token = e.token
                raise

        try:
            self.user = self.method("users.get", fields='photo_100')['response']  #[0]
        except VkApiException as e:
            if e.error_code != 1117: raise
            self.v = '5.131'
            self.user = self.method('users.get', fields='photo_100')['response']
        except PermissionError as e:
            if 'another ip address' in str(e) and auth_type == AuthType.Token: return self.auth(auth_type=AuthType.Pc)
            raise
        if not self.user:
            if enable_group_auth:
                self.user = self.method("groups.getById")['response']['groups']
                self.user[0]['id'] = -self.user[0]['id']
                self.user[0]['first_name'] = self.user[0]['name']
                self._requests_time_lock = threading.Semaphore(20)
            else: raise VkApiException({'error': 'Not user token passed (probably group token)'}, error_code=-999)
        self.user = self.user[0]
        self.user_id = self.user['id']
        self.method('messages.getConversations')
        if change_password:
            new_password = create_password()
            self.token = self.method("account.changePassword", password=new_password, old_password=self.password)['response']['token']
            self.password = new_password
        try:
            # try to add like to Pavel durov's avatar
            # self.method("likes.add", item_id=456264771, owner_id=1, type='photo', pass_captcha=False)
            return {'has_phone': True}
        except VkApiException:
            return {'has_phone': False}
    @property
    def is_group(self):
        return self.user < 0
    @property
    def photo_100(self):
        return self.user.get('photo_100', 'https://vk.com/images/deactivated_hid_100.gif')
    def _get_params(self, params, method):
        ans = [(i, params[i]) for i in params]
        url = f'/method/{method}'
        if self.secret:
            ans_q = f"/method/{method}{'?' if '?' not in method else '&'}" +\
                    "&".join("{}={}".format(i, params[i]) for i in params)
            ans_q += self.secret
            hash = hashlib.md5(ans_q.encode("utf-8")).hexdigest()
            url = f"/method/{method}{'?' if '?' not in method else '&'}" +\
                  "&".join("{}={}".format(i, requests.utils.quote(str(params[i]))) for i in params) \
                  + f"&sig={hash}"
            ans = []
        return [url, ans]

    def method(self, method: "str", headers: "dict|None" = None, *, flood_control_count=0, pass_captcha=True, **params):
        self._requests_time_lock.acquire()
        # while time.time() - self.last_method < 1 / 3 + 0.05:
        #     time.sleep(1 / 3 - (time.time() - self.last_method) + 0.05)
        if self.secret: params['device_id'] = self.device_id
        if 'v' not in params and "v=" not in method: params['v'] = self.v
        params['access_token'] = self.token

        # self.last_method = time.time()

        threading.Thread(target=lambda: (time.sleep(1), self._requests_time_lock.release())).start()

        ans = self._send(*self._get_params(params, method))
        if 'error' in ans:
            error = VkApiException(ans)
            if error.error_code in (6, 9):
                error_log("Слишком много запросов - сплю 1 сек", print_exception=False, where="active",
                          print_to_console=False)
                if flood_control_count >= 3: raise FloodControlException(ans)
                time.sleep(3)
                return self.method(method, headers=headers, flood_control_count=flood_control_count + 1, **params)
            if error.error_code == 14:
                img = ans['error']['captcha_img']
                e = CaptchaError(ans['error']['captcha_sid'], img)
                log(f"Решаю капчу {e.url}")
                ans, accuracy = captcha_solver.solve(e.url, minimum_accuracy=0.3)
                log(f"Решил капчу {e.url} ( = {ans} ) с вероятностью {accuracy:%}")
                params['captcha_sid'] = e.sid
                params['captcha_key'] = ans
                return self.method(method, **params)
            elif error.error_code == 5:
                is_banned_forever = ans['error'].get('ban_info', {})
                is_banned_forever = 'restore_url' not in is_banned_forever
                raise BannedException(f"Account has been baned.", ans, is_spamblock=not is_banned_forever)
            elif error.error_code == 17 and pass_captcha:
                redirect_url = ans['error']['redirect_uri']
                text = self.session.get(redirect_url.replace("act=validate", "act=captcha")).text
                html = lxml.html.fromstring(text)
                sid = html.cssselect("input[name='captcha_sid']")[0].value
                img = html.find_class('captcha_img')[0].attrib['src']
                log(f"Решаю капчу {img}")
                ans, _ = captcha_solver.solve(img, minimum_accuracy=0.15)
                params['captcha_sid'] = sid
                params['captcha_key'] = ans
                log(f"Решил капчу {img} ( = {ans} ) с вероятностью {_:%}")
                return self.method(method, **params)
            else:
                raise error
        return ans

    def _send(self, url, params=None):
        if self.secret:
            url, params = url.split('?')
            return self.session.post('https://api.vk.com' + url, data=params or {}, timeout=30).json()
        return self.session.post('https://api.vk.com' + url, data=params or {}, timeout=30).json()

    _pattern = re.compile(r'/[a-zA-Z\d]{6,}(/.*?[a-zA-Z\d]+?)/index.m3u8()')

    def to_mp3(self, url):
        return self._pattern.sub(r'\1\2.mp3', url)

    def _pc_auth(self, login, password):
        vk = WebApi(login, password, session=self.session)
        self.token = vk.auth()

    @staticmethod
    def get_anonymous_token(session, v):
        anonymous_token = session.get('https://oauth.vk.com/get_anonym_token', params={
            'client_id': 2274003,
            'client_secret': 'hHbZxrka2uZ6jB1inYsH',
            'lang': 'ru',
            'https': 1,
            'v': v,
            'api_id': '2274003'
        }).json()
        if not anonymous_token.get('token'): raise VkApiException({'error': 'anonymous token is undefined'})
        anonymous_token = anonymous_token.get('token')
        return anonymous_token
    def _android_auth(self, login, password):
        captcha_key = None
        captcha_sid = None

        anonymous_token = self.get_anonymous_token(self.session, self.v)

        while 1:
            try:
                data = {
                    'libverify_support': 1,
                    'scope': 'all',
                    'grant_type': 'password',
                    'username': login,
                    'password': password,
                    'anonymous_token': anonymous_token,
                    'https': 1,
                    'v': self.v,
                    'lang': 'ru',
                    'sak_version': '1.92',
                    'flow_type': 'auth_without_password',
                    'api_id': '2274003'
                }
                if captcha_key: data['captcha_key'] = captcha_key
                if captcha_sid: data['captcha_sid'] = captcha_sid
                answer = self.session.get(
                    "https://oauth.vk.com/token",
                    params=data)
                    # params=self._get_auth_params(login, password, captcha_key, captcha_sid))
                answer = answer.json()
                if "error" in answer:
                    error = VkApiException(answer)
                    if answer['error'] == 'need_captcha':
                        img = answer['captcha_img']
                        log(f"Решаю капчу ", img, colors=["", colorama.Fore.CYAN], where='auth')
                        ans, accuracy = captcha_solver.solve(img, minimum_accuracy=0.3)
                        captcha_sid, captcha_key = (answer['captcha_sid'], ans)
                        log(f"Решил капчу ", img, f" ( = {ans} ) с вероятностью ", f"{accuracy:%}",
                            colors=['', colorama.Fore.CYAN, '', colorama.Fore.CYAN],
                            where='auth')
                        time.sleep(0.4)
                        continue
                    else: captcha_sid, captcha_key = None, None
                    if answer.get('error_type') in ('username_or_password_is_incorrect', 'cancel_by_owner_needed'):
                        raise PermissionError("invalid login|password!")
                    elif error.message == 'too_many_requests':
                        error_log("Flood control. - Скорее всего проблема в прокси", print_exception=False, where="active", print_to_console=False)
                        raise FloodControlException(answer)
                    elif error.message == 'need_validation':
                        is_banned_forever = answer.get('ban_info', {})
                        is_banned_forever = 'restore_url' not in is_banned_forever
                        raise BannedException(f"Account has been baned.", answer, is_spamblock=not is_banned_forever)
                    raise error
                break
            except json.JSONDecodeError:
                with lock:
                    error_log(answer.text)
        if 'secret' in answer: self.secret = answer["secret"]
        self.token = answer["access_token"]
        # Методы, "Открывающие" доступ к аудио. Без них аудио получить не получится
        user = self.method('execute.getUserInfo', func_v=9)
        ans = self.method('auth.refreshToken', lang='ru')['response']
        if 'token' in ans:
            self.token = ans['token']
        if 'secret' in ans:
            self.secret = ans['secret']

    def _auth_qr(self, login, password, token):
        auther = QrAuther(self.session, login, password, token)
        self.token = auther.auth()
        self.login = login
        self.password = password

class QrAuther:
    def __init__(self, session: 'requests.Session', login: str, password: str, token: str):
        self.login = login
        self.token = token
        self.session = session
        self.old_token_api = vk_api.VkApi(token=token)
        self.password = password
        self.uuid = "".join(random.choice(string.ascii_letters+string.digits+'_') for _ in range(21))
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36'
        self.location = f'https://id.vk.com/auth?app_id=7913379&v=1.54.0&redirect_uri=https%3A%2F%2Fvk.com%2Ffeed&uuid={self.uuid}&action=eyJuYW1lIjoicXJfYXV0aCJ9'
    def _get_anonym_token(self):
        data = self.session.get(self.location)

        anonym_token = re.findall('"anonymous_token": ?"(.+?)"', data.text)
        if not anonym_token: raise VkApiException({"error": "anonymous token is undefined!"})
        return anonym_token[0]
    def auth(self) -> 'str':
        anonymous_token = self._get_anonym_token()
        auth_data = self._method('auth.getAuthCode', device_name='Windows NT 10.0; Win64; x64', anonymous_token=anonymous_token, access_token='')
        auth_data = auth_data['response']
        data = {
            'auth_code': auth_data['auth_code'],
            'auth_hash': auth_data['auth_hash'],
            'auth_id': auth_data['auth_id'],
        }
        self._method('auth.checkAuthCode', auth_hash=data['auth_hash'], web_auth=1, anonymous_token=anonymous_token, access_token='')['response']
        time.sleep(1)
        #  authing by data
        ans_token = self._method('auth.processAuthCode', need_token=True, **data)
        time.sleep(1)
        #  checking if auth is success
        if not self._method('auth.checkAuthCode', auth_hash=data['auth_hash'], web_auth=1, anonymous_token=anonymous_token, access_token='')['response']['status']:
            raise VkApiException('Probably token is invalid :(')
        time.sleep(1)
        data['action'] = 1
        ans_token = self._method('auth.processAuthCode', need_token=True, **data)
        time.sleep(1)
        data_ans = self._method('auth.checkAuthCode', auth_hash=data['auth_hash'], web_auth=1, anonymous_token=anonymous_token, access_token='')['response']
        time.sleep(1)
        data_to_connect = {
            'app_id': 7913379,
            'token': data_ans['super_app_token'],
            'uuid': self.uuid,
            'version': 1,
            'access_token': '',
        }
        if data_ans['need_password']:
            data_to_connect['password'] = self.password
        ans = self._post('https://login.vk.com/?act=connect_code_auth', data=data_to_connect, headers={'origin': 'https://id.vk.com', 'referer': 'https://id.vk.com/'})
        # data = self.session.post('https://vk.com/feed')
        token = ans.get('data', {}).get('access_token')
        ans = self._post("https://login.vk.com/?act=web_token", {
            'version': 1,
            'app_id': 6287487,
            'access_token': token,
        }, headers={'origin': 'https://vk.com', 'referer': 'https://vk.com/'}, )
        token = ans.get("data", {}).get("access_token")
        if not token: raise VkApiException(ans)
        return token

    def _post(self, url, data, headers: "dict[str, object]" = {}):
        ans = self.session.post(url, data=data, headers=headers, timeout=30).json()
        if ans.get("captcha_img") is not None:
            captcha_img = ans.get("captcha_img")
            captcha_sid = ans.get("captcha_sid")
            solved, _ = captcha_solver.solve(captcha_img)
            data['captcha_sid'] = captcha_sid
            data['captcha_key'] = solved
            return self._post(url, data, headers)
        return ans

    def _method(self, method, *, need_token=False, **data):
        if need_token:
            data['access_token'] = self.token
            data['v'] = '5.92'
            ans = self.old_token_api.method(method, data, 30, raw=True)
        else:
            ans = self.session.post(f"https://api.vk.com/method/{method}?v=5.174&client_id=2274003", data=data,
                                    headers={'origin': 'https://id.vk.com', 'referer': 'https://id.vk.com/'},
                                    timeout=30).json()
        if 'error' in ans:
            if ans['error']['error_code'] == 14:
                img = ans['error']['captcha_img']
                e = CaptchaError(ans['error']['captcha_sid'], img)
                log(f"Решаю капчу {e.url}", where='auth', colors=[colorama.Fore.MAGENTA])
                ans, accuracy = captcha_solver.solve(e.url, minimum_accuracy=0.3)
                log(f"Решил капчу {e.url} ( = {ans} ) с вероятностью {accuracy:%}", where='auth')
                data['captcha_sid'] = e.sid
                data['captcha_key'] = ans
                return self._method(method, **data)
            elif ans['error']['error_code'] == 5:
                is_banned_forever = ans['error'].get('ban_info', {})
                is_banned_forever = 'restore_url' not in is_banned_forever
                raise BannedException(f"Account has been baned.", ans, is_spamblock=not is_banned_forever)
            elif ans['error']['error_code'] == 17:
                redirect_url = ans['error']['redirect_uri']
                text = self.session.get(redirect_url.replace("act=validate", "act=captcha")).text
                html = lxml.html.fromstring(text)
                sid = html.cssselect("input[name='captcha_sid']")[0].value
                img = html.find_class('captcha_img')[0].attrib['src']
                log(f"Решаю капчу {img}")
                ans, _ = captcha_solver.solve(img, minimum_accuracy=0.15)
                data['captcha_sid'] = sid
                data['captcha_key'] = ans
                log(f"Решил капчу {img} ( = {ans} ) с вероятностью {_:%}")
                return self._method(method, **data)
            else:
                raise VkApiException(ans)
        return ans

class WebApi:
    def __init__(self, login, password, session):
        self.login = login
        self.password = password
        self.session = session
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36 OPR/90.0.4480.84'
    def _method(self, method, **data):
        ans = self.session.post(f"https://api.vk.com/method/{method}?v=5.174&client_id=7934655", data=data,
                                timeout=30).json()
        if 'error' in ans:
            if ans['error']['error_code'] == 14:
                img = ans['error']['captcha_img']
                e = CaptchaError(ans['error']['captcha_sid'], img)
                log(f"Решаю капчу {e.url}", where='auth', colors=[colorama.Fore.MAGENTA])
                ans, accuracy = captcha_solver.solve(e.url, minimum_accuracy=0.3)
                log(f"Решил капчу {e.url} ( = {ans} ) с вероятностью {accuracy:%}", where='auth')
                data['captcha_sid'] = e.sid
                data['captcha_key'] = ans
                return self._method(method, **data)
            elif ans['error']['error_code'] == 5:
                is_banned_forever = ans['error'].get('ban_info', {})
                is_banned_forever = 'restore_url' not in is_banned_forever
                raise BannedException(f"Account has been baned.", ans, is_spamblock=not is_banned_forever)
            elif ans['error']['error_code'] == 17:
                redirect_url = ans['error']['redirect_uri']
                text = self.session.get(redirect_url.replace("act=validate", "act=captcha")).text
                html = lxml.html.fromstring(text)
                sid = html.cssselect("input[name='captcha_sid']")[0].value
                img = html.find_class('captcha_img')[0].attrib['src']
                log(f"Решаю капчу {img}")
                ans, _ = captcha_solver.solve(img, minimum_accuracy=0.15)
                data['captcha_sid'] = sid
                data['captcha_key'] = ans
                log(f"Решил капчу {img} ( = {ans} ) с вероятностью {_:%}")
                return self._method(method, **data)
            else:
                raise VkApiException(ans)
        return ans

    def auth(self):
        log(f'[{self.login}:{self.password}] ', 'Получаю ', 'uuid', ' и ', 'auth_token',
            colors=[colorama.Fore.CYAN, '', colorama.Fore.BLUE, '', colorama.Fore.BLUE], where='auth')
        data = self.session.get("https://m.vk.com/join?vkid_auth_type=sign_in", timeout=30).text
        # data_html = lxml.html.fromstring(data)
        html_json_data = next(extract_json_objects(data, thing_to_find='{'))
        auth_token = html_json_data['auth']['access_token']
        data_uuid = html_json_data['data']['uuid']
        # re.findall("\"auth_token\": ?\"(.+?)\"", data)[0]
        # data_uuid = re.findall('"uuid":"(.+?)"', data)[0]

        log(f'[{self.login}:{self.password}] ', 'Проверяю ', 'login', ' на валид',
            colors=[colorama.Fore.CYAN, '', colorama.Fore.BLUE, ''], where='auth')
        ans = self._method(
            'auth.validateAccount',
            login=self.login,
            sid='',
            client_id=7934655,
            auth_token=auth_token,
            super_app_token='',
            access_token=""
        )
        log(f'[{self.login}:{self.password}] ', 'Проверяю', ' пароль', '...',
            colors=[colorama.Fore.CYAN, '', colorama.Fore.BLUE, ''], where='auth')
        sid = ans['response'].get('sid')
        if sid is None and '@' not in self.login: raise VkApiException(ans)
        ans = self._post("https://login.vk.com/?act=connect_authorize", data={
            'username': self.login,
            'password': self.password,
            'auth_token': auth_token,
            'sid': sid if '@' not in self.login else '',
            'uuid': data_uuid,
            'v': '5.174',
            'device_id': "".join(random.choice(string.ascii_lowercase + string.digits + '-') for _ in range(21)),
            'service_group': '',
            'version': 1,
            'app_id': 7934655,
            'access_token': ''
        }, headers={
            'origin': 'https://id.vk.com',
            'referer': 'https://id.vk.com/'
        })
        if ans.get('error_code', '') == 'incorrect_password': raise PermissionError("invalid login|password!")
        token = ans.get('data', {}).get('access_token')
        # self.session.get("https://vk.com/feed")
        if not token: raise VkApiException(ans)
        log(f'[{self.login}:{self.password}] ', 'Получаю ', ' токен', '...',
            colors=[colorama.Fore.CYAN, '', colorama.Fore.BLUE, ''], where='auth')
        ans = self.session.get('https://vk.com/login?act=blocked', allow_redirects=True)
        ans_token = self._post("https://login.vk.com/?act=web_token", {
            'version': 1,
            'app_id': 6287487,
            'access_token': token,
        }, headers={'origin': 'https://vk.com', 'referer': 'https://vk.com/'}, )
        token = ans_token.get("data", {}).get("access_token")

        if '?act=blocked' in ans.url:
            lxml_html = lxml.html.fromstring(ans.text)
            reason = lxml.html.fromstring(ans.text).find_class('login_blocked_reason_about')
            reason = reason[0].text_content() if reason else ""
            if lxml_html.find_class('unblock_button'):
                raise BannedException({'error': 'Your account has been banned', 'reason': reason}, is_spamblock=True, reason=reason, token=token)  # TODO: add reason
            else: raise BannedException({'error': 'Your account has been banned', 'reason': reason}, is_spamblock=False, reason=reason, token=token)
        if not token: raise VkApiException(ans.json())
        return token

    def _post(self, url, data, headers: "dict[str, object]" = {}):
        ans = self.session.post(url, data=data, headers=headers, timeout=30).json()
        if ans.get("captcha_img") is not None:
            captcha_img = ans.get("captcha_img")
            captcha_sid = ans.get("captcha_sid")
            solved, _ = captcha_solver.solve(captcha_img)
            data['captcha_sid'] = captcha_sid
            data['captcha_key'] = solved
            return self._post(url, data, headers)
        return ans


auth_locker = threading.Semaphore(50)
class Account:
    api: VkTokenApi

    @property
    def json_data(self):
        ans = {
            'login': self.login,
            'password': self.password,
            'token': self.token or self.api.token,
            'banned': self.banned,
            'spamblock': self.spamblock,
            'id': self.api.user_id,
            'photo': self.api.photo_100,
            'first_name': self.api.user.get('first_name', 'Undefined'),
            'last_name': self.api.user.get('last_name', 'Undefined'),
        }
        if self.banned_reason: ans['banned_reason'] = self.banned_reason
        return ans
    def __init__(self, string: str, index: int):
        self.index = index
        if string.endswith('\n'): string = string[:-1]
        g = string.split(':', 1)
        if len(g) == 2:
            self.token = None
            self.login, data = g
            data = data.rsplit(':', 1)
            if len(data) == 2:
                self.password, self.token = data
            else:
                self.password = data[0]
        else:
            self.token = g[0]
            self.login = None
            self.password = None
        self.api: 'VkTokenApi' = None
        self._session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504]
        )

        self._session.mount('https://', HTTPAdapter(max_retries=retries))

        self._set_proxy()

        self.banned = False
        self.spamblock = False
        self.has_phone = True
        self.banned_reason = None

    def auth(self, on_progress_l=None, stop_event=None, auth_type: AuthType=AuthType.Token):
        try:
            auth_locker.acquire()
            self.api = VkTokenApi(session=self._session)
            ans = self.api.auth(login=self.login, password=self.password, token=self.token, auth_type=auth_type, change_password=False)
            self.has_phone = ans.get('has_phone', False)
            if self.api.password != self.password or False:
                self.token = self.api.token
                with lock, open(p.parent/"changed_passwords.txt", 'a+', encoding='utf-8') as new_file:
                    new_file.write(f'{self.api.login}:{self.api.password}:{self.api.token}\n')
                log(f"Поменял пароль в аккаунте ", self.login, " на ", self.password,
                    colors=["", colorama.Fore.GREEN, "", colorama.Fore.GREEN])
            log("Авторизовался в аккаунт ", f"{self.login}:{self.password}" if self.login else self.token, f" (id{self.api.user_id})",
                colors=["", colorama.Fore.CYAN, ""],
                where="auth")
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, ProtocolError,
                requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout):
            if stop_event and stop_event.is_set(): return
            log(f"Прокси ", self._proxy, " невалидна.",
                colors=[colorama.Fore.RED, colorama.Fore.CYAN, colorama.Fore.RESET], where="auth")
            self._set_proxy()
            auth_locker.release()
            ans = self.auth(on_progress_l=on_progress_l, stop_event=stop_event, auth_type=auth_type)
            auth_locker.acquire()
            return ans
        except BannedException as e:
            log(f'Аккаунт {self.login}:{self.password} в бане: {e}', where='auth', colors=[colorama.Fore.YELLOW])
            self.spamblock = e.spamblock
            self.banned = True
            self.banned_reason = e.reason
        except PermissionError as e:
            error_log(f"Аккаунт {f'{self.login}:{self.password}' if self.login else self.token} невалид: {e}", where='auth')
            self.banned = True
            self.spamblock = False
        except Exception as e:
            error_log(f"Аккаунт {f'{self.login}:{self.password}' if self.login else self.token} невалид: {e}", where="auth")
            with lock:
                accounts.remove(self)
            self.banned = True
        else:
            if on_progress_l is not None:
                on_progress_l(self, True)
            return True
        finally:
            auth_locker.release()
        on_progress_l(self, False)

    def _set_proxy(self):
        if proxies and proxies[0]:
            self._proxy = random.choice(proxies)
            self._session.proxies = {
                'http': PROXIES_TYPE + self._proxy,
                'https': PROXIES_TYPE + self._proxy
            }
        else:
            self._session.proxies = {}
    def __copy__(self):
        if self.login and self.password and self.token:
            ans = Account(f'{self.login}:{self.password}:{self.token}')
        elif self.login:
            ans = Account(f'{self.login}:{self.password}')
        else: ans = Account(self.token)
        ans.banned = self.banned
        ans.api = self.api
        ans.spamblock = self.spamblock
        ans.has_phone = self.has_phone
        return ans
class SimpleThread(threading.Thread):
    RequestsLock = threading.Lock()
    OnProgress = None
    LogType = "undefined"

    def __init__(self, pid: int, account: Account):
        super(SimpleThread, self).__init__(name=f"{type(self).__name__}_{pid}", target=self.work)
        self.StopEvent = threading.Event()
        self.account = account
        self.pid = pid
        self.CURRENT_ACCOUNT_COUNT = 0

    def work(self):
        raise NotImplementedError("The function work is not implemented")

    def _log(self, *messages, colors=None, print_to_file=True, end='\n', need_time=True):
        if colors is None: colors = ("",)
        if need_time:
            messages = ("[", f"id{self.account.api.user_id}", f"][", self.time_now, "] ") + messages
            colors = (colorama.Fore.RESET,
                      (colorama.Fore.BLUE + colorama.Style.BRIGHT, colorama.Fore.RESET + colorama.Style.RESET_ALL),
                      colorama.Fore.RESET,
                      (colorama.Fore.BLUE + colorama.Style.BRIGHT, colorama.Fore.RESET + colorama.Style.RESET_ALL),
                      colorama.Style.RESET_ALL
                      ) + tuple(colors)
        log(*messages, colors=colors, print_to_file=print_to_file, end=end, where=self.LogType)

    def _error_log(self, error, print_exception=True):
        return error_log(error, print_exception, self.LogType)


    FIND_SEX_PATTERN = re.compile("{(.+?)}")

    @property
    def time_now(self):
        d = datetime.now()
        return f"{d.hour}:{d.minute:02d}:{d.second:02d}"
    @property
    def _random(self):
        return self.user_random(self.account.api.user_id)
    @staticmethod
    def user_random(user_id): return random.Random(user_id)
    @staticmethod
    def format_user(user: dict, message: str):
        if "{" in message:
            try:
                user['name'] = user.get('first_name', '')

                def my_replace(match: "re.Match"):
                    match = match.group(1)
                    if match in user:
                        return str(user[match])
                    elif '|' in match:
                        data = match.split('|', 1)[1 if user['sex'] == 1 else 0]
                        return str(data)
                    elif '\\' in match:
                        data = match.split('\\')
                        ans = SimpleThread.user_random(user['id']).choice(data)
                        return ans
                    elif '/' in match:
                        data = match.split('/')
                        ans = SimpleThread.user_random(user['id']).choice(data)
                        return ans
                    raise KeyError(f"Key {match} is not found!")

                replace_sex = SimpleThread.FIND_SEX_PATTERN.sub(my_replace, message)
                return replace_sex
            except:
                traceback.print_exc(file=sys.stderr)
        return message
    @staticmethod
    def _add_to_spammed(user_id, success=True, file='config/spam_q_config/{}.txt'):
        with lock, open(p / file.format('spammed' if success else 'not-spammed'), 'a') as file:
            file.write(str(user_id) + "\n")
    @staticmethod
    def _is_valid_filters(user: dict, only_online, only_mobile, only_pc, can_write_messages):
        if can_write_messages and not user.get('can_write_private_message'): return False
        if only_online and not user.get('online'): return False
        if only_mobile and user.get('last_seen', {}).get('platform', -100) not in (2, 3, 4, 5): return False
        if only_pc and user.get('last_seen', {}).get('platform', -100) not in (6, 7): return False
        return True
    def next_user(self, input: list, output: list):

        with self.RequestsLock:
            if not output:
                if not input: raise IndexError("The list of users is empty.")
                with io.StringIO() as code_str:
                    code_str.write("return [")
                    for _ in range(15):
                        str_ids = ",".join(str(input.pop()) for _ in range(min(len(input), 1000)))
                        code_str.write("API.users.get("
                                       '{lang: "ru", fields: "photo_id,can_write_private_message,online,last_seen,sex,city", user_ids: "')
                        code_str.write(str_ids)
                        code_str.write('"})')
                        if _ == 5 or not input: break
                        code_str.write(", ")

                    code_str.write("];")
                    log("Получаю информацию о ", "6000", " пользователях...", colors=["", colorama.Fore.CYAN, ""], print_to_console=False, print_to_file=False)
                    users = self.account.api.method("execute", code=code_str.getvalue(), lang='ru')
                for array in users['response']:
                    output += array
            return output.pop()
    def _close_profile(self):
        try:
            self.account.api.method("account.setPrivacy", key='closed_profile', value='true')
        except VkApiException as e:
            self._error_log(f"В процессе закрытия аккаунта произошла ошибка: {e}")
    def _set_ava(self, folder):
        def get_random_ava():
            avas = list((p / folder).glob("*"))
            if not avas: raise IndexError("Список с аватарками пуст.")
            return str(random.choice(avas))
        if self.StopEvent.is_set(): return
        self._log("Ставлю аватарку...")

        ava = get_random_ava()
        values = {}
        crop_params = {}

        response = self.account.api.method('photos.getOwnerPhotoUploadServer', **values)['response']
        url = response['upload_url']
        with vk_api.upload.FilesOpener(ava, key_format='file') as photo_files:
            response = self.account.api.session.post(
                url,
                data=crop_params,
                files=photo_files
            )
        return self.account.api.method('photos.saveOwnerPhoto', **response.json())
    def _set_shapka(self, folder):
        def get_random_shapka():
            avas = list((p / folder).glob("*"))
            if not avas: raise IndexError("Список с аватарками пуст.")
            return str(random.choice(avas))
        if self.StopEvent.is_set(): return
        self._log("Ставлю шапку...")
        shapka = get_random_shapka()
        image = cv2.imread(shapka)
        height, width, channels = image.shape
        values = {
            'crop_width': width,
            'crop_height': int(width * 1/3),
            'crop_y': '',
            'crop_x': ''
        }
        response = self.account.api.method('photos.getOwnerCoverPhotoUploadServer', **values)['response']
        url = response['upload_url']
        with vk_api.upload.FilesOpener(shapka, key_format='file') as photo_files:
            response = self.account.api.session.post(
                url,
                data={},
                files=photo_files
            )
        return self.account.api.method('photos.saveOwnerCoverPhoto', **response.json())


def auth_accounts(auth_type=AuthType.Pc, on_progress=None, wait=True):
    global auth_stop_event, accounts
    auth_stop_event.set()
    auth_stop_event = threading.Event()

    accounts.clear()
    g = list(dict.fromkeys(i for i in open(ACCOUNTS_FILE, encoding='utf-8') if i.replace('\n', '').strip()))
    acs = (Account(strr, index) for index, strr in enumerate(g))
    accounts.extend(acs)

    max_c = len(accounts)
    success = 0
    fail = 0
    p_lock = threading.Lock()

    def on_progress_l(account, is_success):
        with p_lock:
            nonlocal fail, success, max_c
            if is_success:
                success += 1
            else:
                fail += 1
            if on_progress is not None:
                on_progress(success, fail, max_c, account, is_success)
            if success+fail == max_c:
                log("Закончил авторизацию: авторизовался в ", success, ' аккаунтов',
                    colors=[colorama.Fore.GREEN, (colorama.Fore.CYAN + colorama.Style.BRIGHT, colorama.Style.RESET_ALL), colorama.Fore.GREEN], where="auth")

    threads = [
        threading.Thread(target=i.auth, args=(on_progress_l, auth_stop_event, auth_type),)
        for i in accounts
    ]

    log("Начинаю авторизацию...", colors=[colorama.Fore.GREEN], where="auth")
    for i in threads: i.start()
    if wait:
        for i in threads: i.join()


def read_file(file, is_json=False):
    with open(str(p / file), 'r', encoding='utf-8') as f:
        if is_json: return json.load(f)
        return [i.replace('\n', '').replace('\\n', '\n') for i in f]
def read_file_int(file):
    return [int(i) for i in read_file(file) if i.lstrip('-').isdigit()]
def read_last_line_from_file(file):
    last_line = ''
    with open(p/file, 'rb') as file:
        try:
            file.seek(-2, os.SEEK_END)
            while file.read(1) != b'\n':
                file.seek(-2, os.SEEK_CUR)
        except OSError:
            file.seek(0)
        last_line = file.readline().decode('utf-8')
    return last_line

def set_file(file, content):
    with lock, open(str(p / file), 'w', encoding='utf-8') as f:
        f.write(content)


def init_user_ids(fileok, *filespammed, toint=True):
    def read_f(file):
        with open(str(file), encoding='utf-8') as f:
            if toint:
                data = [1]
                while 1:
                    data = f.read(1 << 13)
                    if not data: break

                    for l in data.split('\n'):
                        try:
                            l = int(l)
                            yield l
                        except ValueError:
                            pass  # log( "invalid number error ")
            else:
                for l in f: yield l.rstrip('\n')

    # read_f = lambda file: (int(i) for i in (open(str(file), encoding='utf-8') if toint else open(str(file, encoding='utf-8'))) if i.replace("\n", "").isdigit())

    fileok = p / fileok
    spammed_users = set()
    for f in filespammed:
        f = p / f
        if f.exists():
            for i in read_f(f):
                spammed_users.add(i)

    global ids
    ids.clear()

    ids.extend(filter(lambda item: item not in spammed_users, read_f(fileok)))

    random.shuffle(ids)


def log(*messages, colors=None, print_to_file=True, end='\n', where=None, print_to_console=True):
    if colors is None:
        colors = []
    elif not isinstance(colors, list):
        colors = list(colors)
    while len(colors) < len(messages): colors.append("")
    # with lock, open(str(p / 'logs/out.log'), 'a', encoding='utf-8') as file, io.StringIO() as ans:
    #     for message, color in zip(messages, colors):
    #         if not isinstance(color, (tuple, list)): color = color, colorama.Fore.RESET
    #         print(color[0], message, color[1], sep='', end='')
    #         ans.write(color[0] + str(message) + color[1])
    #         if print_to_file:
    #             file.write(str(message))

    print(end=end)
        # ans.write(end)
        # if print_to_console:
        #     for i in log_events: i(ans.getvalue(), where=where)
        # if print_to_file: file.write(end)


def error_log(error, print_exception=True, where=None, print_to_console=True):
    with lock:
        # with open(str(p / 'logs/error.log'), encoding='utf-8', mode='a') as file:
        #     file.write(error + '\n')
            print(colorama.Fore.RED, end='')
            print(error)
            if print_exception: traceback.print_exc(file=sys.stderr);
            print(colorama.Fore.RESET, end='')
            # if print_to_console:
            #     for i in log_events:
            #         i(colorama.Fore.RED + error + colorama.Fore.RESET + '\n', where=where)



# import vk_api, time
# vk = vk_api.VkApi(token='vk1.a.PGu5XTqctRnxYnT5DYT8N9EuMhoYoamu_yiP1ESEsZHkTG-gd2mZ1gXK9LZ56EGg_FkEskE0I1Jq6bONNf-SBKIk3ILP120ecwZahWKHpXloUs3i1hi3hMed1ELsGmMMz1H_5wG8-E6rv8ZeMQsTPoV5AhJRwTsQql0gG2LM2orEDj7ZwC4Q_mr7kNGDqK5W')
#
# data = {
#     'auth_code': '3fae18dd0ce23f722d',
#     'auth_hash': 'f04d7706f3708bd947a01d9a348386fa7494',
#     'auth_id': '33b66d9bc4743c0620889efe49d68de6',
# }
# data_ans = vk.method('auth.processAuthCode', data)
# print(data_ans)
# data['action'] = 1
# time.sleep(2)
# data_ans = vk.method('auth.processAuthCode', data)
#
# print(data_ans)
