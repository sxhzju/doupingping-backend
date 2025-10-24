#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import json
import sys
import time
import random
import re
import base64
import hashlib
import logging
from typing import Union, Any
import datetime
from urllib.parse import urlencode, quote

try:
    import httpx
except ImportError:
    print('Error: httpx is required but not installed.')
    print('Please install it using: pip install httpx')
    sys.exit(1)
try:
    from pydantic import BaseModel
except ImportError:
    print('Error: pydantic is required but not installed.')
    print('Please install it using: pip install pydantic')
    sys.exit(1)
try:
    from gmssl import sm3, func
except ImportError:
    print('Error: gmssl is required but not installed.')
    print('Please install it using: pip install gmssl')
from constants import APIEndpoints, DefaultConfig, ErrorCodes, SignatureConstants, LoggingConstants, TokenConstants, RegexPatterns, TimezoneConstants, DOUYIN_COOKIE, NetworkConfig, HeadersConfig, DeviceConfig, LoggingConfig, TokenConfig, SignatureConfig, OutputConfig, ErrorHandlingConfig, ValidationConfig

class ConfigManager:
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self.load_config()

    def load_config(self, config_path: str=None) -> dict:
        self._config = self._get_default_config()
        return self._config

    def _get_default_config(self) -> dict:
        headers = HeadersConfig.get_headers()
        headers['Cookie'] = DOUYIN_COOKIE
        return {
            'network': {
                'timeout': NetworkConfig.TIMEOUT,
                'max_retries': NetworkConfig.MAX_RETRIES,
                'max_connections': NetworkConfig.MAX_CONNECTIONS,
                'max_keepalive_connections': NetworkConfig.MAX_KEEPALIVE_CONNECTIONS,
                'max_tasks': NetworkConfig.MAX_TASKS,
                'proxies': {
                    'http': NetworkConfig.HTTP_PROXY,
                    'https': NetworkConfig.HTTPS_PROXY,
                },
            },
            'headers': headers,
            'device': DeviceConfig.get_device_info(),
            'api': {
                'douyin_domain': APIEndpoints.DOUYIN_DOMAIN,
                'iesdouyin_domain': APIEndpoints.IESDOUYIN_DOMAIN,
                'live_domain': APIEndpoints.LIVE_DOMAIN,
                'live_domain2': APIEndpoints.LIVE_DOMAIN2,
                'sso_domain': APIEndpoints.SSO_DOMAIN,
                'webcast_wss_domain': APIEndpoints.WEBCAST_WSS_DOMAIN,
                'endpoints': {
                    'post_comment': '/aweme/v1/web/comment/list/',
                    'user_detail': '/aweme/v1/web/user/profile/other/',
                    'ms_token': APIEndpoints.MS_TOKEN_URL,
                    'ttwid': APIEndpoints.TTWID_URL,
                },
            },
            'pagination': {
                'default_cursor': DefaultConfig.DEFAULT_CURSOR,
                'default_count': DefaultConfig.DEFAULT_COUNT,
            },
            'logging': {
                'level': LoggingConfig.LEVEL,
                'log_dir': LoggingConfig.LOG_DIR,
                'format': LoggingConfig.FORMAT,
                'max_bytes': LoggingConfig.MAX_BYTES,
                'backup_count': LoggingConfig.BACKUP_COUNT,
                'console_output': LoggingConfig.CONSOLE_OUTPUT,
                'console_level': LoggingConfig.CONSOLE_LEVEL,
            },
            'output': {
                'save_original': OutputConfig.SAVE_ORIGINAL,
                'save_simplified': OutputConfig.SAVE_SIMPLIFIED,
                'comment_original_file': OutputConfig.COMMENT_ORIGINAL_FILE,
                'comment_simplified_file': OutputConfig.COMMENT_SIMPLIFIED_FILE,
                'user_original_file': OutputConfig.USER_ORIGINAL_FILE,
                'user_simplified_file': OutputConfig.USER_SIMPLIFIED_FILE,
                'video_original_file': OutputConfig.VIDEO_ORIGINAL_FILE,
                'video_simplified_file': OutputConfig.VIDEO_SIMPLIFIED_FILE,
                'indent': OutputConfig.INDENT,
                'ensure_ascii': OutputConfig.ENSURE_ASCII,
            },
            'validation': {
                'sec_user_id': {
                    'min_length': ValidationConfig.SEC_USER_ID_MIN_LENGTH,
                    'pattern': ValidationConfig.SEC_USER_ID_PATTERN,
                },
                'aweme_id': {
                    'pattern': ValidationConfig.AWEME_ID_PATTERN,
                },
            },
        }

    def get_config_value(self, key: str, default=None) -> Any:
        if self._config is None:
            self.load_config()
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def validate_config(self, config: dict=None) -> bool:
        if config is None:
            config = self._config
        if not config:
            return False
        required_keys = ['network', 'headers', 'device', 'api']
        for key in required_keys:
            if key not in config:
                print(f'Missing required configuration key: {key}')
                return False
        return True

    @property
    def config(self) -> dict:
        if self._config is None:
            self.load_config()
        return self._config

class LoggerManager:
    _loggers = {}
    _initialized = False

    @classmethod
    def setup_logger(cls, name: str='douyin_crawler', level: str=None) -> logging.Logger:
        if name in cls._loggers:
            return cls._loggers[name]
        config_manager = ConfigManager()
        log_config = config_manager.get_config_value('logging', {})
        if level is None:
            level = log_config.get('level', LoggingConstants.INFO)
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        if logger.handlers:
            cls._loggers[name] = logger
            return logger
        log_format = log_config.get('format', LoggingConstants.DETAILED_FORMAT)
        formatter = logging.Formatter(log_format)
        console_handler = logging.StreamHandler()
        console_level = log_config.get('console_level', LoggingConstants.INFO)
        console_handler.setLevel(getattr(logging, console_level.upper()))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        cls._loggers[name] = logger
        cls._initialized = True
        return logger

    @classmethod
    def log_request(cls, url: str, method: str, status_code: int, logger_name: str='douyin_crawler'):
        logger = cls.setup_logger(logger_name)
        logger.info(f'Request: {method} {url} - Status: {status_code}')

    @classmethod
    def log_error(cls, error: Exception, context: dict=None, logger_name: str='douyin_crawler'):
        logger = cls.setup_logger(logger_name)
        error_msg = f'Error: {str(error)}'
        if context:
            error_msg += f' - Context: {context}'
        logger.error(error_msg, exc_info=True)

class APIError(Exception):

    def __init__(self, message: str, code: str=None, context: dict=None):
        self.message = message
        self.code = code or ErrorCodes.API_RESPONSE_ERROR
        self.context = context or {}
        super().__init__(self.message)

    def display_error(self):
        logger = LoggerManager.setup_logger()
        logger.error(f'API Error [{self.code}]: {self.message}')
        if self.context:
            logger.error(f'Context: {self.context}')

class APIConnectionError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_CONNECTION_ERROR, context)

class APIResponseError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_RESPONSE_ERROR, context)

class APITimeoutError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_TIMEOUT_ERROR, context)

class APIUnavailableError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_UNAVAILABLE_ERROR, context)

class APIUnauthorizedError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_UNAUTHORIZED_ERROR, context)

class APINotFoundError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_NOT_FOUND_ERROR, context)

class APIRateLimitError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_RATE_LIMIT_ERROR, context)

class APIRetryExhaustedError(APIError):

    def __init__(self, message: str, context: dict=None):
        super().__init__(message, ErrorCodes.API_RETRY_EXHAUSTED_ERROR, context)

class TokenManager:

    @staticmethod
    def gen_false_msToken() -> str:
        base_str = TokenConstants.MS_TOKEN_BASE_STR
        length = TokenConstants.MS_TOKEN_LENGTH
        return ''.join((random.choice(base_str) for _ in range(length))) + '=='

class VerifyFpManager:

    @classmethod
    def gen_verify_fp(cls) -> str:
        base_str = TokenConstants.VERIFY_FP_BASE_STR
        t = len(base_str)
        milliseconds = int(round(time.time() * 1000))
        base36 = ''
        while milliseconds > 0:
            remainder = milliseconds % 36
            if remainder < 10:
                base36 = str(remainder) + base36
            else:
                base36 = chr(ord('a') + remainder - 10) + base36
            milliseconds = int(milliseconds / 36)
        r = base36
        o = [''] * 36
        o[8] = o[13] = o[18] = o[23] = '_'
        o[14] = '4'
        for i in range(36):
            if not o[i]:
                n = 0 or int(random.random() * t)
                if i == 19:
                    n = 3 & n | 8
                o[i] = base_str[n]
        return TokenConstants.VERIFY_FP_PREFIX + r + '_' + ''.join(o)

    @classmethod
    def gen_s_v_web_id(cls) -> str:
        return cls.gen_verify_fp()

class XBogus:

    def __init__(self, user_agent: str=None) -> None:
        self.Array = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, 10, 11, 12, 13, 14, 15]
        self.character = SignatureConstants.XBOGUS_CHARACTER
        self.ua_key = b'\x00\x01\x0c'
        self.user_agent = user_agent if user_agent is not None and user_agent != '' else DefaultConfig.DEFAULT_HEADERS['User-Agent']

    def md5_str_to_array(self, md5_str):
        if isinstance(md5_str, str) and len(md5_str) > 32:
            return [ord(char) for char in md5_str]
        else:
            array = []
            idx = 0
            while idx < len(md5_str):
                array.append(self.Array[ord(md5_str[idx])] << 4 | self.Array[ord(md5_str[idx + 1])])
                idx += 2
            return array

    def md5_encrypt(self, url_path):
        hashed_url_path = self.md5_str_to_array(self.md5(self.md5_str_to_array(self.md5(url_path))))
        return hashed_url_path

    def md5(self, input_data):
        if isinstance(input_data, str):
            array = self.md5_str_to_array(input_data)
        elif isinstance(input_data, list):
            array = input_data
        else:
            raise ValueError('Invalid input type. Expected str or list.')
        md5_hash = hashlib.md5()
        md5_hash.update(bytes(array))
        return md5_hash.hexdigest()

    def encoding_conversion(self, a, b, c, e, d, t, f, r, n, o, i, _, x, u, s, l, v, h, p):
        y = [a]
        y.append(int(i))
        y.extend([b, _, c, x, e, u, d, s, t, l, f, v, r, h, n, p, o])
        re = bytes(y).decode('ISO-8859-1')
        return re

    def encoding_conversion2(self, a, b, c):
        return chr(a) + chr(b) + c

    def rc4_encrypt(self, key, data):
        S = list(range(256))
        j = 0
        encrypted_data = bytearray()
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            (S[i], S[j]) = (S[j], S[i])
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            (S[i], S[j]) = (S[j], S[i])
            encrypted_byte = byte ^ S[(S[i] + S[j]) % 256]
            encrypted_data.append(encrypted_byte)
        return encrypted_data

    def calculation(self, a1, a2, a3):
        x1 = (a1 & 255) << 16
        x2 = (a2 & 255) << 8
        x3 = x1 | x2 | a3
        return self.character[(x3 & 16515072) >> 18] + self.character[(x3 & 258048) >> 12] + self.character[(x3 & 4032) >> 6] + self.character[x3 & 63]

    def getXBogus(self, url_path):
        array1 = self.md5_str_to_array(self.md5(base64.b64encode(self.rc4_encrypt(self.ua_key, self.user_agent.encode('ISO-8859-1'))).decode('ISO-8859-1')))
        array2 = self.md5_str_to_array(self.md5(self.md5_str_to_array('d41d8cd98f00b204e9800998ecf8427e')))
        url_path_array = self.md5_encrypt(url_path)
        timer = int(time.time())
        ct = 536919696
        array3 = []
        array4 = []
        xb_ = ''
        new_array = [64, 0.00390625, 1, 12, url_path_array[14], url_path_array[15], array2[14], array2[15], array1[14], array1[15], timer >> 24 & 255, timer >> 16 & 255, timer >> 8 & 255, timer & 255, ct >> 24 & 255, ct >> 16 & 255, ct >> 8 & 255, ct & 255]
        xor_result = new_array[0]
        for i in range(1, len(new_array)):
            b = new_array[i]
            if isinstance(b, float):
                b = int(b)
            xor_result ^= b
        new_array.append(xor_result)
        idx = 0
        while idx < len(new_array):
            array3.append(new_array[idx])
            try:
                array4.append(new_array[idx + 1])
            except IndexError:
                pass
            idx += 2
        merge_array = array3 + array4
        garbled_code = self.encoding_conversion2(2, 255, self.rc4_encrypt('ÿ'.encode('ISO-8859-1'), self.encoding_conversion(*merge_array).encode('ISO-8859-1')).decode('ISO-8859-1'))
        idx = 0
        while idx < len(garbled_code):
            xb_ += self.calculation(ord(garbled_code[idx]), ord(garbled_code[idx + 1]), ord(garbled_code[idx + 2]))
            idx += 3
        self.params = '%s&X-Bogus=%s' % (url_path, xb_)
        self.xb = xb_
        return (self.params, self.xb, self.user_agent)

class ABogus:
    __filter = re.compile(RegexPatterns.URL_FILTER)
    __arguments = SignatureConstants.ABOGUS_ARGUMENTS
    __ua_key = SignatureConstants.ABOGUS_UA_KEY
    __end_string = SignatureConstants.ABOGUS_END_STRING
    __version = SignatureConstants.ABOGUS_VERSION
    __browser = SignatureConstants.ABOGUS_BROWSER
    __reg = SignatureConstants.ABOGUS_REG
    __str = SignatureConstants.ABOGUS_STR

    def __init__(self):
        self.chunk = []
        self.size = 0
        self.reg = self.__reg[:]
        self.ua_code = [76, 98, 15, 131, 97, 245, 224, 133, 122, 199, 241, 166, 79, 34, 90, 191, 128, 126, 122, 98, 66, 11, 14, 40, 49, 110, 110, 173, 67, 96, 138, 252]
        self.browser = self.__browser
        self.browser_len = len(self.browser)
        self.browser_code = self.char_code_at(self.browser)

    @classmethod
    def list_1(cls, random_num=None, a=170, b=85, c=45) -> list:
        return cls.random_list(random_num, a, b, 1, 2, 5, c & a)

    @classmethod
    def list_2(cls, random_num=None, a=170, b=85) -> list:
        return cls.random_list(random_num, a, b, 1, 0, 0, 0)

    @classmethod
    def list_3(cls, random_num=None, a=170, b=85) -> list:
        return cls.random_list(random_num, a, b, 1, 0, 5, 0)

    @staticmethod
    def random_list(a: float=None, b=170, c=85, d=0, e=0, f=0, g=0) -> list:
        import random as random_module
        r = a or random_module.random() * 10000
        v = [r, int(r) & 255, int(r) >> 8]
        s = v[1] & b | d
        v.append(s)
        s = v[1] & c | e
        v.append(s)
        s = v[2] & b | f
        v.append(s)
        s = v[2] & c | g
        v.append(s)
        return v[-4:]

    @staticmethod
    def from_char_code(*args):
        return ''.join((chr(code) for code in args))

    @classmethod
    def generate_string_1(cls, random_num_1=None, random_num_2=None, random_num_3=None):
        return cls.from_char_code(*cls.list_1(random_num_1)) + cls.from_char_code(*cls.list_2(random_num_2)) + cls.from_char_code(*cls.list_3(random_num_3))

    def generate_string_2(self, url_params: str, method='GET', start_time=0, end_time=0) -> str:
        a = self.generate_string_2_list(url_params, method, start_time, end_time)
        e = self.end_check_num(a)
        a.extend(self.browser_code)
        a.append(e)
        return self.rc4_encrypt(self.from_char_code(*a), 'y')

    def generate_string_2_list(self, url_params: str, method='GET', start_time=0, end_time=0) -> list:
        import random as random_module
        start_time = start_time or int(time.time() * 1000)
        end_time = end_time or start_time + random_module.randint(4, 8)
        params_array = self.generate_params_code(url_params)
        method_array = self.generate_method_code(method)
        return self.list_4(end_time >> 24 & 255, params_array[21], self.ua_code[23], end_time >> 16 & 255, params_array[22], self.ua_code[24], end_time >> 8 & 255, end_time >> 0 & 255, start_time >> 24 & 255, start_time >> 16 & 255, start_time >> 8 & 255, start_time >> 0 & 255, method_array[21], method_array[22], int(end_time / 256 / 256 / 256 / 256) >> 0, int(start_time / 256 / 256 / 256 / 256) >> 0, self.browser_len)

    @staticmethod
    def reg_to_array(a):
        o = [0] * 32
        for i in range(8):
            c = a[i]
            o[4 * i + 3] = 255 & c
            c >>= 8
            o[4 * i + 2] = 255 & c
            c >>= 8
            o[4 * i + 1] = 255 & c
            c >>= 8
            o[4 * i] = 255 & c
        return o

    def compress(self, a):
        f = self.generate_f(a)
        i = self.reg[:]
        for o in range(64):
            c = self.de(i[0], 12) + i[4] + self.de(self.pe(o), o)
            c = c & 4294967295
            c = self.de(c, 7)
            s = (c ^ self.de(i[0], 12)) & 4294967295
            u = self.he(o, i[0], i[1], i[2])
            u = u + i[3] + s + f[o + 68] & 4294967295
            b = self.ve(o, i[4], i[5], i[6])
            b = b + i[7] + c + f[o] & 4294967295
            i[3] = i[2]
            i[2] = self.de(i[1], 9)
            i[1] = i[0]
            i[0] = u
            i[7] = i[6]
            i[6] = self.de(i[5], 19)
            i[5] = i[4]
            i[4] = (b ^ self.de(b, 9) ^ self.de(b, 17)) & 4294967295
        for l in range(8):
            self.reg[l] = (self.reg[l] ^ i[l]) & 4294967295

    @classmethod
    def generate_f(cls, e):
        r = [0] * 132
        for t in range(16):
            r[t] = e[4 * t] << 24 | e[4 * t + 1] << 16 | e[4 * t + 2] << 8 | e[4 * t + 3]
            r[t] &= 4294967295
        for n in range(16, 68):
            a = r[n - 16] ^ r[n - 9] ^ cls.de(r[n - 3], 15)
            a = a ^ cls.de(a, 15) ^ cls.de(a, 23)
            r[n] = (a ^ cls.de(r[n - 13], 7) ^ r[n - 6]) & 4294967295
        for n in range(68, 132):
            r[n] = (r[n - 68] ^ r[n - 64]) & 4294967295
        return r

    @staticmethod
    def pad_array(arr, length=60):
        while len(arr) < length:
            arr.append(0)
        return arr

    def fill(self, length=60):
        size = 8 * self.size
        self.chunk.append(128)
        self.chunk = self.pad_array(self.chunk, length)
        for i in range(4):
            self.chunk.append(size >> 8 * (3 - i) & 255)

    @staticmethod
    def list_4(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, i: int, j: int, k: int, m: int, n: int, o: int, p: int, q: int, r: int) -> list:
        return [44, a, 0, 0, 0, 0, 24, b, n, 0, c, d, 0, 0, 0, 1, 0, 239, e, o, f, g, 0, 0, 0, 0, h, 0, 0, 14, i, j, 0, k, m, 3, p, 1, q, 1, r, 0, 0, 0]

    @staticmethod
    def end_check_num(a: list):
        r = 0
        for i in a:
            r ^= i
        return r

    @classmethod
    def decode_string(cls, url_string):
        decoded = cls.__filter.sub(cls.replace_func, url_string)
        return decoded

    @staticmethod
    def replace_func(match):
        return chr(int(match.group(1), 16))

    @staticmethod
    def de(e, r):
        r %= 32
        return e << r & 4294967295 | e >> 32 - r

    @staticmethod
    def pe(e):
        return 2043430169 if 0 <= e < 16 else 2055708042

    @staticmethod
    def he(e, r, t, n):
        if 0 <= e < 16:
            return (r ^ t ^ n) & 4294967295
        elif 16 <= e < 64:
            return (r & t | r & n | t & n) & 4294967295
        raise ValueError

    @staticmethod
    def ve(e, r, t, n):
        if 0 <= e < 16:
            return (r ^ t ^ n) & 4294967295
        elif 16 <= e < 64:
            return (r & t | ~r & n) & 4294967295
        raise ValueError

    @staticmethod
    def convert_to_char_code(a):
        d = []
        for i in a:
            d.append(ord(i))
        return d

    @staticmethod
    def split_array(arr, chunk_size=64):
        result = []
        for i in range(0, len(arr), chunk_size):
            result.append(arr[i:i + chunk_size])
        return result

    @staticmethod
    def char_code_at(s):
        return [ord(char) for char in s]

    def write(self, e):
        self.size = len(e)
        if isinstance(e, str):
            e = self.decode_string(e)
            e = self.char_code_at(e)
        if len(e) <= 64:
            self.chunk = e
        else:
            chunks = self.split_array(e, 64)
            for i in chunks[:-1]:
                self.compress(i)
            self.chunk = chunks[-1]

    def reset(self):
        self.chunk = []
        self.size = 0
        self.reg = self.__reg[:]

    def sum(self, e, length=60):
        self.reset()
        self.write(e)
        self.fill(length)
        self.compress(self.chunk)
        return self.reg_to_array(self.reg)

    @classmethod
    def generate_result_unit(cls, n, s):
        r = ''
        for (i, j) in zip(range(18, -1, -6), (16515072, 258048, 4032, 63)):
            r += cls.__str[s][(n & j) >> i]
        return r

    @classmethod
    def generate_result_end(cls, s, e='s4'):
        r = ''
        b = ord(s[120]) << 16
        r += cls.__str[e][(b & 16515072) >> 18]
        r += cls.__str[e][(b & 258048) >> 12]
        r += '=='
        return r

    @classmethod
    def generate_result(cls, s, e='s4'):
        r = []
        for i in range(0, len(s), 3):
            if i + 2 < len(s):
                n = ord(s[i]) << 16 | ord(s[i + 1]) << 8 | ord(s[i + 2])
            elif i + 1 < len(s):
                n = ord(s[i]) << 16 | ord(s[i + 1]) << 8
            else:
                n = ord(s[i]) << 16
            for (j, k) in zip(range(18, -1, -6), (16515072, 258048, 4032, 63)):
                if j == 6 and i + 1 >= len(s):
                    break
                if j == 0 and i + 2 >= len(s):
                    break
                r.append(cls.__str[e][(n & k) >> j])
        r.append('=' * ((4 - len(r) % 4) % 4))
        return ''.join(r)

    @classmethod
    def generate_args_code(cls):
        a = []
        for j in range(24, -1, -8):
            a.append(cls.__arguments[0] >> j)
        a.append(cls.__arguments[1] / 256)
        a.append(cls.__arguments[1] % 256)
        a.append(cls.__arguments[1] >> 24)
        a.append(cls.__arguments[1] >> 16)
        for j in range(24, -1, -8):
            a.append(cls.__arguments[2] >> j)
        return [int(i) & 255 for i in a]

    def generate_method_code(self, method: str='GET') -> list[int]:
        return self.sm3_to_array(self.sm3_to_array(method + self.__end_string))

    def generate_params_code(self, params: str) -> list[int]:
        return self.sm3_to_array(self.sm3_to_array(params + self.__end_string))

    @classmethod
    def sm3_to_array(cls, data: Union[str, list]) -> list[int]:
        if isinstance(data, str):
            b = data.encode('utf-8')
        else:
            b = bytes(data)
        h = sm3.sm3_hash(func.bytes_to_list(b))
        return [int(h[i:i + 2], 16) for i in range(0, len(h), 2)]

    @staticmethod
    def rc4_encrypt(plaintext, key):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + ord(key[i % len(key)])) % 256
            (s[i], s[j]) = (s[j], s[i])
        i = 0
        j = 0
        cipher = []
        for k in range(len(plaintext)):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            (s[i], s[j]) = (s[j], s[i])
            t = (s[i] + s[j]) % 256
            cipher.append(chr(s[t] ^ ord(plaintext[k])))
        return ''.join(cipher)

    def get_value(self, url_params: Union[dict, str], method='GET', start_time=0, end_time=0, random_num_1=None, random_num_2=None, random_num_3=None) -> str:
        string_1 = self.generate_string_1(random_num_1, random_num_2, random_num_3)
        string_2 = self.generate_string_2(urlencode(url_params) if isinstance(url_params, dict) else url_params, method, start_time, end_time)
        string = string_1 + string_2
        return self.generate_result(string, 's4')

class BogusManager:

    @classmethod
    def xb_str_2_endpoint(cls, endpoint: str, user_agent: str) -> str:
        try:
            final_endpoint = XBogus(user_agent).getXBogus(endpoint)
        except Exception as e:
            raise RuntimeError('生成X-Bogus失败: {0}'.format(e))
        return final_endpoint[0]

    @classmethod
    def xb_model_2_endpoint(cls, base_endpoint: str, params: dict, user_agent: str) -> str:
        if not isinstance(params, dict):
            raise TypeError('参数必须是字典类型')
        param_str = '&'.join([f'{k}={v}' for (k, v) in params.items()])
        try:
            xb_value = XBogus(user_agent).getXBogus(param_str)
        except Exception as e:
            raise RuntimeError('生成X-Bogus失败: {0}'.format(e))
        separator = '&' if '?' in base_endpoint else '?'
        final_endpoint = f'{base_endpoint}{separator}{param_str}&X-Bogus={xb_value[1]}'
        return final_endpoint

    @classmethod
    def ab_model_2_endpoint(cls, params: dict, user_agent: str) -> str:
        if not isinstance(params, dict):
            raise TypeError('参数必须是字典类型')
        try:
            ab_value = ABogus().get_value(params)
        except Exception as e:
            raise RuntimeError('生成A-Bogus失败: {0}'.format(e))
        return quote(ab_value, safe='')

class BaseRequestModel(BaseModel):
    device_platform: str = 'webapp'
    aid: str = '6383'
    channel: str = 'channel_pc_web'
    pc_client_type: int = 1
    version_code: str = '290100'
    version_name: str = '29.1.0'
    cookie_enabled: str = 'true'
    screen_width: int = 1920
    screen_height: int = 1080
    browser_language: str = 'zh-CN'
    browser_platform: str = 'Win32'
    browser_name: str = 'Chrome'
    browser_version: str = '130.0.0.0'
    browser_online: str = 'true'
    engine_name: str = 'Blink'
    engine_version: str = '130.0.0.0'
    os_name: str = 'Windows'
    os_version: str = '10'
    cpu_core_num: int = 12
    device_memory: int = 8
    platform: str = 'PC'
    downlink: str = '10'
    effective_type: str = '4g'
    from_user_page: str = '1'
    locate_query: str = 'false'
    need_time_list: str = '1'
    pc_libra_divert: str = 'Windows'
    publish_video_strategy_type: str = '2'
    round_trip_time: str = '0'
    show_live_replay_strategy: str = '1'
    time_list_query: str = '0'
    whale_cut_token: str = ''
    update_version_code: str = '170400'
    msToken: str = ''
    verifyFp: str = ''

    def __init__(self, **data):
        if not data.get('msToken'):
            data['msToken'] = TokenManager.gen_false_msToken()
        if not data.get('verifyFp'):
            data['verifyFp'] = VerifyFpManager.gen_verify_fp()
        super().__init__(**data)

class PostComments(BaseRequestModel):
    aweme_id: str
    cursor: int = 0
    count: int = 20
    item_type: int = 0
    insert_ids: str = ''
    whale_cut_token: str = ''
    cut_version: int = 1
    rcFT: str = ''

class UserProfile(BaseRequestModel):
    sec_user_id: str

class BaseCrawler:

    def __init__(self, proxies: dict=None, max_retries: int=None, max_connections: int=None, timeout: int=None, max_tasks: int=None, crawler_headers: dict=None):
        config_manager = ConfigManager()
        network_config = config_manager.get_config_value('network', {})
        if isinstance(proxies, dict):
            self.proxies = proxies
        else:
            proxy_config = network_config.get('proxies', {})
            self.proxies = {}
            if proxy_config.get('http'):
                self.proxies['http://'] = proxy_config['http']
            if proxy_config.get('https'):
                self.proxies['https://'] = proxy_config['https']
            self.proxies = self.proxies if self.proxies else None
        self.crawler_headers = crawler_headers or config_manager.get_config_value('headers', {})
        self._max_tasks = max_tasks or network_config.get('max_tasks', DefaultConfig.DEFAULT_MAX_TASKS)
        self.semaphore = asyncio.Semaphore(self._max_tasks)
        self._max_connections = max_connections or network_config.get('max_connections', DefaultConfig.DEFAULT_MAX_CONNECTIONS)
        self.limits = httpx.Limits(max_connections=self._max_connections)
        self._max_retries = max_retries or network_config.get('max_retries', DefaultConfig.DEFAULT_MAX_RETRIES)
        self.atransport = httpx.AsyncHTTPTransport(retries=self._max_retries)
        self._timeout = timeout or network_config.get('timeout', DefaultConfig.DEFAULT_TIMEOUT)
        self.timeout = httpx.Timeout(self._timeout)
        client_kwargs = {'headers': self.crawler_headers, 'timeout': self.timeout, 'limits': self.limits, 'transport': self.atransport}
        if self.proxies:
            client_kwargs['mounts'] = self.proxies
        self.aclient = httpx.AsyncClient(**client_kwargs)
        self.logger = LoggerManager.setup_logger('BaseCrawler')

    async def fetch_response(self, endpoint: str) -> httpx.Response:
        return await self.get_fetch_data(endpoint)

    async def fetch_get_json(self, endpoint: str) -> dict:
        response = await self.get_fetch_data(endpoint)
        return self.parse_json(response)

    async def fetch_post_json(self, endpoint: str, params: dict={}, data=None) -> dict:
        response = await self.post_fetch_data(endpoint, params, data)
        return self.parse_json(response)

    def parse_json(self, response: httpx.Response) -> dict:
        if response is not None and isinstance(response, httpx.Response) and (response.status_code == 200):
            try:
                return response.json()
            except json.JSONDecodeError as e:
                match = re.search(RegexPatterns.JSON_MATCH, response.text)
                try:
                    return json.loads(match.group())
                except (json.JSONDecodeError, AttributeError) as e:
                    self.logger.error(f'解析 {response.url} 接口 JSON 失败： {e}')
                    raise APIResponseError('解析JSON数据失败')
        else:
            if isinstance(response, httpx.Response):
                self.logger.error(f'获取数据失败。状态码: {response.status_code}')
            else:
                self.logger.error(f'无效响应类型。响应类型: {type(response)}')
            raise APIResponseError('获取数据失败')

    async def get_fetch_data(self, url: str):
        for attempt in range(self._max_retries):
            try:
                self.logger.debug(f'GET请求: {url} (尝试 {attempt + 1}/{self._max_retries})')
                response = await self.aclient.get(url, follow_redirects=True)
                if not response.text.strip() or not response.content:
                    error_message = f'第 {attempt + 1} 次响应内容为空, 状态码: {response.status_code}, URL:{response.url}'
                    self.logger.warning(error_message)
                    if attempt == self._max_retries - 1:
                        raise APIRetryExhaustedError('获取端点数据失败, 次数达到上限')
                    await asyncio.sleep(self._timeout)
                    continue
                LoggerManager.log_request(str(response.url), 'GET', response.status_code)
                response.raise_for_status()
                return response
            except httpx.RequestError as e:
                error_msg = f'连接端点失败，检查网络环境或代理：{url} 代理：{self.proxies}'
                self.logger.error(error_msg)
                raise APIConnectionError(error_msg, {'url': url, 'proxies': self.proxies})
            except httpx.HTTPStatusError as http_error:
                self.handle_http_status_error(http_error, url, attempt + 1)
            except APIError as e:
                e.display_error()
                raise

    async def post_fetch_data(self, url: str, params: dict={}, data=None):
        for attempt in range(self._max_retries):
            try:
                self.logger.debug(f'POST请求: {url} (尝试 {attempt + 1}/{self._max_retries})')
                response = await self.aclient.post(url, json=None if not params else dict(params), data=None if not data else data, follow_redirects=True)
                if not response.text.strip() or not response.content:
                    error_message = f'第 {attempt + 1} 次响应内容为空, 状态码: {response.status_code}, URL:{response.url}'
                    self.logger.warning(error_message)
                    if attempt == self._max_retries - 1:
                        raise APIRetryExhaustedError('获取端点数据失败, 次数达到上限')
                    await asyncio.sleep(self._timeout)
                    continue
                LoggerManager.log_request(str(response.url), 'POST', response.status_code)
                response.raise_for_status()
                return response
            except httpx.RequestError as e:
                error_msg = f'连接端点失败，检查网络环境或代理：{url} 代理：{self.proxies}'
                self.logger.error(error_msg)
                raise APIConnectionError(error_msg, {'url': url, 'proxies': self.proxies})
            except httpx.HTTPStatusError as http_error:
                self.handle_http_status_error(http_error, url, attempt + 1)
            except APIError as e:
                e.display_error()
                raise

    def handle_http_status_error(self, http_error, url: str, attempt):
        response = getattr(http_error, 'response', None)
        status_code = getattr(response, 'status_code', None)
        if response is None or status_code is None:
            self.logger.error(f'HTTP状态错误: {http_error}, URL: {url}, 尝试次数: {attempt}')
            raise APIResponseError(f'处理HTTP错误时遇到意外情况: {http_error}')
        if status_code == 302:
            pass
        elif status_code == 404:
            raise APINotFoundError(f'HTTP Status Code {status_code}')
        elif status_code == 503:
            raise APIUnavailableError(f'HTTP Status Code {status_code}')
        elif status_code == 408:
            raise APITimeoutError(f'HTTP Status Code {status_code}')
        elif status_code == 401:
            raise APIUnauthorizedError(f'HTTP Status Code {status_code}')
        elif status_code == 429:
            raise APIRateLimitError(f'HTTP Status Code {status_code}')
        else:
            self.logger.error(f'HTTP状态错误: {status_code}, URL: {url}, 尝试次数: {attempt}')
            raise APIResponseError(f'HTTP状态错误: {status_code}')

    async def close(self):
        await self.aclient.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclient.aclose()

class DouyinWebCrawler:

    def __init__(self):
        self.config_manager = ConfigManager()
        self.logger = LoggerManager.setup_logger('DouyinWebCrawler')

    def get_douyin_headers(self):
        headers_config = self.config_manager.get_config_value('headers', {})
        network_config = self.config_manager.get_config_value('network', {})
        proxy_config = network_config.get('proxies', {})
        proxies = {}
        if proxy_config.get('http'):
            proxies['http://'] = proxy_config['http']
        if proxy_config.get('https'):
            proxies['https://'] = proxy_config['https']
        kwargs = {'headers': headers_config, 'proxies': proxies if proxies else None}
        return kwargs

    async def fetch_video_comments(self, aweme_id: str, cursor: int=0, count: int=20):
        kwargs = self.get_douyin_headers()
        base_crawler = BaseCrawler(proxies=kwargs['proxies'], crawler_headers=kwargs['headers'])
        async with base_crawler as crawler:
            params = PostComments(aweme_id=aweme_id, cursor=cursor, count=count)
            api_domain = self.config_manager.get_config_value('api.douyin_domain', APIEndpoints.DOUYIN_DOMAIN)
            comment_endpoint = self.config_manager.get_config_value('api.endpoints.post_comment', '/aweme/v1/web/comment/list/')
            base_endpoint = api_domain + comment_endpoint
            endpoint = BogusManager.xb_model_2_endpoint(base_endpoint, params.dict(), kwargs['headers']['User-Agent'])
            self.logger.info(f'获取视频评论: aweme_id={aweme_id}, cursor={cursor}, count={count}')
            response = await crawler.fetch_get_json(endpoint)
        return response

    async def fetch_user_profile(self, sec_user_id: str):
        kwargs = self.get_douyin_headers()
        base_crawler = BaseCrawler(proxies=kwargs['proxies'], crawler_headers=kwargs['headers'])
        async with base_crawler as crawler:
            params = UserProfile(sec_user_id=sec_user_id)
            api_domain = self.config_manager.get_config_value('api.douyin_domain', APIEndpoints.DOUYIN_DOMAIN)
            user_endpoint = self.config_manager.get_config_value('api.endpoints.user_detail', '/aweme/v1/web/user/profile/other/')
            base_endpoint = api_domain + user_endpoint
            endpoint = BogusManager.xb_model_2_endpoint(base_endpoint, params.dict(), kwargs['headers']['User-Agent'])
            self.logger.info(f'获取用户资料: sec_user_id={sec_user_id}')
            response = await crawler.fetch_get_json(endpoint)
        return response

    async def fetch_video_data(self, aweme_id: str):
        kwargs = self.get_douyin_headers()
        base_crawler = BaseCrawler(proxies=kwargs['proxies'], crawler_headers=kwargs['headers'])
        async with base_crawler as crawler:
            from urllib.parse import urlencode
            from constants import DeviceConfig, APIEndpoints
            headers = kwargs['headers']
            params = DeviceConfig.get_device_info()
            params['aweme_id'] = aweme_id

            # The endpoint for video details
            endpoint = "https://www.douyin.com/aweme/v1/web/aweme/detail/"

            # Generate the a_bogus signature using BogusManager from utils.py
            # The ab_model_2_endpoint in utils.py handles the full logic including URL encoding
            a_bogus = BogusManager.ab_model_2_endpoint(params, headers["User-Agent"])

            # Construct the final URL
            query_string = urlencode(params)
            full_url = f"{endpoint}?{query_string}&a_bogus={a_bogus}"
            
            self.logger.info(f'获取视频数据: aweme_id={aweme_id}')
            response = await crawler.fetch_get_json(full_url)
        return response

def simplify_video_result(result: dict) -> dict:
    utc8_tz = datetime.timezone(datetime.timedelta(hours=TimezoneConstants.UTC8_OFFSET_HOURS))
    try:
        aweme_detail = result.get('aweme_detail') or {}
        if not aweme_detail:
            return {}

        publish_timestamp = aweme_detail.get('create_time')
        publish_time_str = None
        if publish_timestamp:
            publish_time_str = datetime.datetime.fromtimestamp(publish_timestamp, tz=utc8_tz).strftime(TimezoneConstants.DATETIME_FORMAT)

        response_timestamp_ms = result.get('extra', {}).get('now')
        response_time_str = None
        if response_timestamp_ms:
            response_time_str = datetime.datetime.fromtimestamp(response_timestamp_ms / 1000, tz=utc8_tz).strftime(TimezoneConstants.DATETIME_FORMAT)

        author_info = aweme_detail.get('author') or {}
        stats_info = aweme_detail.get('statistics') or {}
        music_info = aweme_detail.get('music') or {}
        video_info = aweme_detail.get('video') or {}

        cover_urls = []
        cover_data = video_info.get('cover')
        if isinstance(cover_data, dict):
            cover_urls = cover_data.get('url_list', []) or []

        music_cover_urls = []
        music_cover_data = music_info.get('cover_medium')
        if isinstance(music_cover_data, dict):
            music_cover_urls = music_cover_data.get('url_list', []) or []

        return {
            'aweme_id': aweme_detail.get('aweme_id'),
            'title': aweme_detail.get('desc'),
            'region': aweme_detail.get('region'),
            'duration_ms': aweme_detail.get('duration'),
            'publish_time': publish_timestamp,
            'publish_time_utc8': publish_time_str,
            'response_time': response_timestamp_ms,
            'response_time_utc8': response_time_str,
            'author': {
                'nickname': author_info.get('nickname'),
                'unique_id': author_info.get('unique_id'),
                'sec_uid': author_info.get('sec_uid'),
                'uid': author_info.get('uid'),
            },
            'statistics': {
                'play_count': stats_info.get('play_count'),
                'digg_count': stats_info.get('digg_count'),
                'comment_count': stats_info.get('comment_count'),
                'share_count': stats_info.get('share_count'),
                'forward_count': stats_info.get('forward_count'),
            },
            'music': {
                'title': music_info.get('title'),
                'author': music_info.get('author'),
                'cover_urls': music_cover_urls,
            },
            'cover_urls': cover_urls,
            'share_url': aweme_detail.get('share_info', {}).get('share_url'),
        }
    except Exception as exc:
        logger = LoggerManager.setup_logger('DataProcessor')
        logger.error(f'简化视频数据时发生错误: {exc}', exc_info=True)
        return {}

def simplify_comment_result(result: dict) -> dict:
    utc8_tz = datetime.timezone(datetime.timedelta(hours=TimezoneConstants.UTC8_OFFSET_HOURS))
    extracted_comments = []
    if result and isinstance(result.get('comments'), list):
        for comment in result.get('comments', []):
            creation_time = datetime.datetime.fromtimestamp(comment['create_time'], tz=utc8_tz)
            reply_comment_total = len(comment.get('reply_comment', [])) if isinstance(comment.get('reply_comment'), list) else 0
            images = []
            if comment.get('image_list') and isinstance(comment.get('image_list'), list):
                for image in comment.get('image_list'):
                    images.append(image.get('origin_url', {}).get('url_list', []))
            extracted_comments.append({'comment_id': comment.get('cid'), 'creation_time_utc8': creation_time.strftime(TimezoneConstants.DATETIME_FORMAT), 'sec_user_id': comment.get('user', {}).get('sec_uid'), 'nickname': comment.get('user', {}).get('nickname'), 'ip_location': comment.get('ip_label'), 'content': comment.get('text'), 'digg_count': comment.get('digg_count'), 'reply_comment_total': reply_comment_total, 'images': images})
    simplified_dict = {'pagination_info': {'total_comments': result.get('total'), 'next_cursor': result.get('cursor'), 'has_more': bool(result.get('has_more'))}, 'comments': extracted_comments}
    return simplified_dict

def save_json_file(data: dict, filename: str, indent: int=2, ensure_ascii: bool=False):
    logger = LoggerManager.setup_logger('DataProcessor')
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
        logger.info(f'数据已保存到文件: {filename}')
    except Exception as e:
        logger.error(f'保存文件失败: {filename}, 错误: {e}')
        raise

def validate_aweme_id(aweme_id: str) -> bool:
    if not aweme_id or not isinstance(aweme_id, str):
        return False
    return re.match(RegexPatterns.AWEME_ID_PATTERN, aweme_id) is not None

def validate_sec_user_id(sec_user_id: str) -> bool:
    if not sec_user_id or not isinstance(sec_user_id, str):
        return False
    config_manager = ConfigManager()
    min_length = config_manager.get_config_value('validation.sec_user_id.min_length', 30)
    if len(sec_user_id) < min_length:
        return False
    pattern = config_manager.get_config_value('validation.sec_user_id.pattern', RegexPatterns.SEC_USER_ID_PATTERN)
    return re.match(pattern, sec_user_id) is not None

def setup_environment():
    config_manager = ConfigManager()
    logger = LoggerManager.setup_logger()
    if not config_manager.validate_config():
        logger.warning('配置验证失败，使用默认配置')
    logger.info('环境设置完成')
    return (config_manager, logger)

def get_current_timestamp() -> str:
    utc8_tz = datetime.timezone(datetime.timedelta(hours=TimezoneConstants.UTC8_OFFSET_HOURS))
    now = datetime.datetime.now(tz=utc8_tz)
    return now.strftime(TimezoneConstants.DATETIME_FORMAT)

def create_output_filename(base_name: str, extension: str='json', add_timestamp: bool=False) -> str:
    if add_timestamp:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        return f'{base_name}_{timestamp}.{extension}'
    else:
        return f'{base_name}.{extension}'
__all__ = ['ConfigManager', 'LoggerManager', 'APIError', 'APIConnectionError', 'APIResponseError', 'APITimeoutError', 'APIUnavailableError', 'APIUnauthorizedError', 'APINotFoundError', 'APIRateLimitError', 'APIRetryExhaustedError', 'TokenManager', 'VerifyFpManager', 'XBogus', 'ABogus', 'BogusManager', 'BaseRequestModel', 'PostComments', 'UserProfile', 'BaseCrawler', 'DouyinWebCrawler', 'simplify_video_result', 'simplify_comment_result', 'save_json_file', 'validate_aweme_id', 'validate_sec_user_id', 'setup_environment', 'get_current_timestamp', 'create_output_filename']
