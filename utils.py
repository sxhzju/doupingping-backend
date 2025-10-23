#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抖音爬虫工具模块
Douyin Crawler Utilities Module

包含配置管理、日志系统、签名算法、网络请求、数据模型等核心功能
Contains configuration management, logging system, signature algorithms, 
network requests, data models and other core functionalities
"""

import asyncio
import json
import os
import sys
import time
import urllib
import random
import re
import base64
import hashlib
import logging
import logging.handlers
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
from urllib.parse import urlencode, quote
import datetime

# Third-party imports
try:
    import httpx
except ImportError:
    print("Error: httpx is required but not installed.")
    print("Please install it using: pip install httpx")
    sys.exit(1)

try:
    from pydantic import BaseModel
except ImportError:
    print("Error: pydantic is required but not installed.")
    print("Please install it using: pip install pydantic")
    sys.exit(1)


try:
    from gmssl import sm3, func
except ImportError:
    print("Error: gmssl is required but not installed.")
    print("Please install it using: pip install gmssl")


# Local imports
from constants import (
    APIEndpoints, DefaultConfig, ErrorCodes, SignatureConstants,
    LoggingConstants, TokenConstants, FilePaths,
    RegexPatterns, TimezoneConstants, DOUYIN_COOKIE,
    NetworkConfig, HeadersConfig, DeviceConfig, LoggingConfig,
    TokenConfig, SignatureConfig, OutputConfig, ErrorHandlingConfig,
    ValidationConfig
)


# ==================== 配置管理模块 (Configuration Management Module) ====================

class ConfigManager:
    """配置管理器 (Configuration Manager) - 使用硬编码配置"""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.load_config()
    
    def load_config(self, config_path: str = None) -> dict:
        """
        加载配置 (Load configuration) - 直接从 constants.py 加载硬编码配置
        
        Args:
            config_path (str): 配置文件路径 (已废弃，保留用于向后兼容)
            
        Returns:
            dict: 配置字典 (Configuration dictionary)
        """
        self._config = self._get_default_config()
        return self._config
    
    def _get_default_config(self) -> dict:
        """
        获取默认配置 (Get default configuration) - 从 constants.py 硬编码配置加载
        
        Returns:
            dict: 默认配置字典 (Default configuration dictionary)
        """
        # 构建请求头，使用硬编码的 Cookie
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
                    'https': NetworkConfig.HTTPS_PROXY
                }
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
                    'ttwid': APIEndpoints.TTWID_URL
                }
            },
            'pagination': {
                'default_cursor': DefaultConfig.DEFAULT_CURSOR,
                'default_count': DefaultConfig.DEFAULT_COUNT
            },
            'logging': {
                'level': LoggingConfig.LEVEL,
                'log_dir': LoggingConfig.LOG_DIR,
                'log_file': LoggingConfig.LOG_FILE,
                'format': LoggingConfig.FORMAT,
                'max_bytes': LoggingConfig.MAX_BYTES,
                'backup_count': LoggingConfig.BACKUP_COUNT,
                'console_output': LoggingConfig.CONSOLE_OUTPUT,
                'console_level': LoggingConfig.CONSOLE_LEVEL
            },
            'output': {
                'save_original': OutputConfig.SAVE_ORIGINAL,
                'save_simplified': OutputConfig.SAVE_SIMPLIFIED,
                'comment_original_file': OutputConfig.COMMENT_ORIGINAL_FILE,
                'comment_simplified_file': OutputConfig.COMMENT_SIMPLIFIED_FILE,
                'user_profile_file': OutputConfig.USER_PROFILE_FILE,
                'indent': OutputConfig.INDENT,
                'ensure_ascii': OutputConfig.ENSURE_ASCII
            },
            'validation': {
                'sec_user_id': {
                    'min_length': ValidationConfig.SEC_USER_ID_MIN_LENGTH,
                    'pattern': ValidationConfig.SEC_USER_ID_PATTERN
                },
                'aweme_id': {
                    'pattern': ValidationConfig.AWEME_ID_PATTERN
                }
            }
        }
    
    def get_config_value(self, key: str, default=None) -> Any:
        """
        获取配置值 (Get configuration value)
        
        Args:
            key (str): 配置键，支持点号分隔的嵌套键 (Configuration key, supports dot-separated nested keys)
            default: 默认值 (Default value)
            
        Returns:
            Any: 配置值 (Configuration value)
        """
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
    
    def validate_config(self, config: dict = None) -> bool:
        """
        验证配置 (Validate configuration)
        
        Args:
            config (dict): 要验证的配置 (Configuration to validate)
            
        Returns:
            bool: 验证结果 (Validation result)
        """
        if config is None:
            config = self._config
        
        if not config:
            return False
        
        # 检查必需的配置项 (Check required configuration items)
        required_keys = ['network', 'headers', 'device', 'api']
        for key in required_keys:
            if key not in config:
                print(f"Missing required configuration key: {key}")
                return False
        
        return True
    
    @property
    def config(self) -> dict:
        """获取完整配置 (Get complete configuration)"""
        if self._config is None:
            self.load_config()
        return self._config


# ==================== 日志系统模块 (Logging System Module) ====================

class LoggerManager:
    """日志管理器 (Logger Manager)"""
    
    _loggers = {}
    _initialized = False
    
    @classmethod
    def setup_logger(cls, name: str = "douyin_crawler", level: str = None) -> logging.Logger:
        """
        设置日志器 (Setup logger)
        
        Args:
            name (str): 日志器名称 (Logger name)
            level (str): 日志级别 (Log level)
            
        Returns:
            logging.Logger: 日志器实例 (Logger instance)
        """
        if name in cls._loggers:
            return cls._loggers[name]
        
        # 获取配置 (Get configuration)
        config_manager = ConfigManager()
        log_config = config_manager.get_config_value('logging', {})
        
        # 设置日志级别 (Set log level)
        if level is None:
            level = log_config.get('level', LoggingConstants.INFO)
        
        # 创建日志器 (Create logger)
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        
        # 避免重复添加处理器 (Avoid duplicate handlers)
        if logger.handlers:
            cls._loggers[name] = logger
            return logger
        
        # 创建格式器 (Create formatter)
        log_format = log_config.get('format', LoggingConstants.DETAILED_FORMAT)
        formatter = logging.Formatter(log_format)
        
        # 仅控制台处理器 (Console-only handler)
        console_handler = logging.StreamHandler()
        console_level = log_config.get('console_level', LoggingConstants.INFO)
        console_handler.setLevel(getattr(logging, console_level.upper()))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        cls._loggers[name] = logger
        cls._initialized = True
        
        return logger
    
    @classmethod
    def log_request(cls, url: str, method: str, status_code: int, logger_name: str = "douyin_crawler"):
        """
        记录请求日志 (Log request)
        
        Args:
            url (str): 请求URL (Request URL)
            method (str): 请求方法 (Request method)
            status_code (int): 状态码 (Status code)
            logger_name (str): 日志器名称 (Logger name)
        """
        logger = cls.setup_logger(logger_name)
        logger.info(f"Request: {method} {url} - Status: {status_code}")
    
    @classmethod
    def log_error(cls, error: Exception, context: dict = None, logger_name: str = "douyin_crawler"):
        """
        记录错误日志 (Log error)
        
        Args:
            error (Exception): 异常对象 (Exception object)
            context (dict): 上下文信息 (Context information)
            logger_name (str): 日志器名称 (Logger name)
        """
        logger = cls.setup_logger(logger_name)
        error_msg = f"Error: {str(error)}"
        if context:
            error_msg += f" - Context: {context}"
        logger.error(error_msg, exc_info=True)


# ==================== 异常处理模块 (Exception Handling Module) ====================

class APIError(Exception):
    """API错误基类 (Base API Error Class)"""
    def __init__(self, message: str, code: str = None, context: dict = None):
        self.message = message
        self.code = code or ErrorCodes.API_RESPONSE_ERROR
        self.context = context or {}
        super().__init__(self.message)
    
    def display_error(self):
        """显示错误信息 (Display error information)"""
        logger = LoggerManager.setup_logger()
        logger.error(f"API Error [{self.code}]: {self.message}")
        if self.context:
            logger.error(f"Context: {self.context}")


class APIConnectionError(APIError):
    """API连接错误 (API Connection Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_CONNECTION_ERROR, context)


class APIResponseError(APIError):
    """API响应错误 (API Response Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_RESPONSE_ERROR, context)


class APITimeoutError(APIError):
    """API超时错误 (API Timeout Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_TIMEOUT_ERROR, context)


class APIUnavailableError(APIError):
    """API不可用错误 (API Unavailable Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_UNAVAILABLE_ERROR, context)


class APIUnauthorizedError(APIError):
    """API未授权错误 (API Unauthorized Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_UNAUTHORIZED_ERROR, context)


class APINotFoundError(APIError):
    """API未找到错误 (API Not Found Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_NOT_FOUND_ERROR, context)


class APIRateLimitError(APIError):
    """API限流错误 (API Rate Limit Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_RATE_LIMIT_ERROR, context)


class APIRetryExhaustedError(APIError):
    """API重试耗尽错误 (API Retry Exhausted Error)"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, ErrorCodes.API_RETRY_EXHAUSTED_ERROR, context)


# ==================== Token管理模块 (Token Management Module) ====================

class TokenManager:
    """Token管理器 (Token Manager)"""
    
    @staticmethod
    def gen_false_msToken() -> str:
        """
        生成随机msToken (Generate random msToken)
        
        Returns:
            str: 随机msToken (Random msToken)
        """
        base_str = TokenConstants.MS_TOKEN_BASE_STR
        length = TokenConstants.MS_TOKEN_LENGTH
        return "".join(random.choice(base_str) for _ in range(length)) + "=="


class VerifyFpManager:
    """VerifyFp管理器 (VerifyFp Manager)"""
    
    @classmethod
    def gen_verify_fp(cls) -> str:
        """
        生成verifyFp与s_v_web_id (Generate verifyFp and s_v_web_id)
        
        Returns:
            str: verifyFp字符串 (verifyFp string)
        """
        base_str = TokenConstants.VERIFY_FP_BASE_STR
        t = len(base_str)
        milliseconds = int(round(time.time() * 1000))
        base36 = ""
        
        while milliseconds > 0:
            remainder = milliseconds % 36
            if remainder < 10:
                base36 = str(remainder) + base36
            else:
                base36 = chr(ord("a") + remainder - 10) + base36
            milliseconds = int(milliseconds / 36)
        
        r = base36
        o = [""] * 36
        o[8] = o[13] = o[18] = o[23] = "_"
        o[14] = "4"
        
        for i in range(36):
            if not o[i]:
                n = 0 or int(random.random() * t)
                if i == 19:
                    n = 3 & n | 8
                o[i] = base_str[n]
        
        return TokenConstants.VERIFY_FP_PREFIX + r + "_" + "".join(o)
    
    @classmethod
    def gen_s_v_web_id(cls) -> str:
        """
        生成s_v_web_id (Generate s_v_web_id)
        
        Returns:
            str: s_v_web_id字符串 (s_v_web_id string)
        """
        return cls.gen_verify_fp()


# ==================== 签名算法模块 (Signature Algorithm Module) ====================

class XBogus:
    """XBogus签名算法类 (XBogus Signature Algorithm Class)"""
    
    def __init__(self, user_agent: str = None) -> None:
        # fmt: off
        self.Array = [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, 10, 11, 12, 13, 14, 15
        ]
        # fmt: on
        self.character = SignatureConstants.XBOGUS_CHARACTER
        self.ua_key = b"\x00\x01\x0c"
        self.user_agent = (
            user_agent
            if user_agent is not None and user_agent != ""
            else DefaultConfig.DEFAULT_HEADERS["User-Agent"]
        )
    
    def md5_str_to_array(self, md5_str):
        """
        将字符串使用md5哈希算法转换为整数数组
        Convert a string to an array of integers using the md5 hashing algorithm
        """
        if isinstance(md5_str, str) and len(md5_str) > 32:
            return [ord(char) for char in md5_str]
        else:
            array = []
            idx = 0
            while idx < len(md5_str):
                array.append(
                    (self.Array[ord(md5_str[idx])] << 4)
                    | self.Array[ord(md5_str[idx + 1])]
                )
                idx += 2
            return array
    
    def md5_encrypt(self, url_path):
        """
        使用多轮md5哈希算法对URL路径进行加密
        Encrypt the URL path using multiple rounds of md5 hashing
        """
        hashed_url_path = self.md5_str_to_array(
            self.md5(self.md5_str_to_array(self.md5(url_path)))
        )
        return hashed_url_path
    
    def md5(self, input_data):
        """
        计算输入数据的md5哈希值
        Calculate the md5 hash value of the input data
        """
        if isinstance(input_data, str):
            array = self.md5_str_to_array(input_data)
        elif isinstance(input_data, list):
            array = input_data
        else:
            raise ValueError("Invalid input type. Expected str or list.")
        
        md5_hash = hashlib.md5()
        md5_hash.update(bytes(array))
        return md5_hash.hexdigest()
    
    def encoding_conversion(
        self, a, b, c, e, d, t, f, r, n, o, i, _, x, u, s, l, v, h, p
    ):
        """
        第一次编码转换
        Perform encoding conversion
        """
        y = [a]
        y.append(int(i))
        y.extend([b, _, c, x, e, u, d, s, t, l, f, v, r, h, n, p, o])
        re = bytes(y).decode("ISO-8859-1")
        return re
    
    def encoding_conversion2(self, a, b, c):
        """
        第二次编码转换
        Perform an encoding conversion on the given input values and return the result
        """
        return chr(a) + chr(b) + c
    
    def rc4_encrypt(self, key, data):
        """
        使用RC4算法对数据进行加密
        Encrypt data using the RC4 algorithm
        """
        S = list(range(256))
        j = 0
        encrypted_data = bytearray()
        
        # 初始化S盒 (Initialize the S box)
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # 生成密文 (Generate the ciphertext)
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            encrypted_byte = byte ^ S[(S[i] + S[j]) % 256]
            encrypted_data.append(encrypted_byte)
        
        return encrypted_data
    
    def calculation(self, a1, a2, a3):
        """
        对给定的输入值执行位运算计算，并返回结果
        Perform a calculation using bitwise operations on the given input values and return the result
        """
        x1 = (a1 & 255) << 16
        x2 = (a2 & 255) << 8
        x3 = x1 | x2 | a3
        return (
            self.character[(x3 & 16515072) >> 18]
            + self.character[(x3 & 258048) >> 12]
            + self.character[(x3 & 4032) >> 6]
            + self.character[x3 & 63]
        )
    
    def getXBogus(self, url_path):
        """
        获取X-Bogus值
        Get the X-Bogus value
        """
        array1 = self.md5_str_to_array(
            self.md5(
                base64.b64encode(
                    self.rc4_encrypt(self.ua_key, self.user_agent.encode("ISO-8859-1"))
                ).decode("ISO-8859-1")
            )
        )
        
        array2 = self.md5_str_to_array(
            self.md5(self.md5_str_to_array("d41d8cd98f00b204e9800998ecf8427e"))
        )
        url_path_array = self.md5_encrypt(url_path)
        
        timer = int(time.time())
        ct = 536919696
        array3 = []
        array4 = []
        xb_ = ""
        # fmt: off
        new_array = [
            64, 0.00390625, 1, 12,
            url_path_array[14], url_path_array[15], array2[14], array2[15], array1[14], array1[15],
            timer >> 24 & 255, timer >> 16 & 255, timer >> 8 & 255, timer & 255,
            ct >> 24 & 255, ct >> 16 & 255, ct >> 8 & 255, ct & 255
        ]
        # fmt: on
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
        
        garbled_code = self.encoding_conversion2(
            2,
            255,
            self.rc4_encrypt(
                "\xff".encode("ISO-8859-1"),
                self.encoding_conversion(*merge_array).encode("ISO-8859-1"),
            ).decode("ISO-8859-1"),
        )
        
        idx = 0
        while idx < len(garbled_code):
            xb_ += self.calculation(
                ord(garbled_code[idx]),
                ord(garbled_code[idx + 1]),
                ord(garbled_code[idx + 2]),
            )
            idx += 3
        self.params = "%s&X-Bogus=%s" % (url_path, xb_)
        self.xb = xb_
        return (self.params, self.xb, self.user_agent)


class ABogus:
    """ABogus签名算法类 (ABogus Signature Algorithm Class)"""
    
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
        # Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
        self.ua_code = [
            76, 98, 15, 131, 97, 245, 224, 133, 122, 199, 241, 166, 79, 34, 90, 191,
            128, 126, 122, 98, 66, 11, 14, 40, 49, 110, 110, 173, 67, 96, 138, 252
        ]
        self.browser = self.__browser
        self.browser_len = len(self.browser)
        self.browser_code = self.char_code_at(self.browser)
    
    @classmethod
    def list_1(cls, random_num=None, a=170, b=85, c=45, ) -> list:
        return cls.random_list(
            random_num,
            a,
            b,
            1,
            2,
            5,
            c & a,
        )
    
    @classmethod
    def list_2(cls, random_num=None, a=170, b=85, ) -> list:
        return cls.random_list(
            random_num,
            a,
            b,
            1,
            0,
            0,
            0,
        )
    
    @classmethod
    def list_3(cls, random_num=None, a=170, b=85, ) -> list:
        return cls.random_list(
            random_num,
            a,
            b,
            1,
            0,
            5,
            0,
        )
    
    @staticmethod
    def random_list(
            a: float = None,
            b=170,
            c=85,
            d=0,
            e=0,
            f=0,
            g=0,
    ) -> list:
        import random as random_module
        r = a or (random_module.random() * 10000)
        v = [
            r,
            int(r) & 255,
            int(r) >> 8,
        ]
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
        return "".join(chr(code) for code in args)
    
    @classmethod
    def generate_string_1(
            cls,
            random_num_1=None,
            random_num_2=None,
            random_num_3=None,
    ):
        return cls.from_char_code(*cls.list_1(random_num_1)) + cls.from_char_code(
            *cls.list_2(random_num_2)) + cls.from_char_code(*cls.list_3(random_num_3))
    
    def generate_string_2(
            self,
            url_params: str,
            method="GET",
            start_time=0,
            end_time=0,
    ) -> str:
        a = self.generate_string_2_list(
            url_params,
            method,
            start_time,
            end_time,
        )
        e = self.end_check_num(a)
        a.extend(self.browser_code)
        a.append(e)
        return self.rc4_encrypt(self.from_char_code(*a), "y")
    
    def generate_string_2_list(
            self,
            url_params: str,
            method="GET",
            start_time=0,
            end_time=0,
    ) -> list:
        import random as random_module
        start_time = start_time or int
        start_time = start_time or int(time.time() * 1000)
        end_time = end_time or (start_time + random_module.randint(4, 8))
        params_array = self.generate_params_code(url_params)
        method_array = self.generate_method_code(method)
        return self.list_4(
            (end_time >> 24) & 255,
            params_array[21],
            self.ua_code[23],
            (end_time >> 16) & 255,
            params_array[22],
            self.ua_code[24],
            (end_time >> 8) & 255,
            (end_time >> 0) & 255,
            (start_time >> 24) & 255,
            (start_time >> 16) & 255,
            (start_time >> 8) & 255,
            (start_time >> 0) & 255,
            method_array[21],
            method_array[22],
            int(end_time / 256 / 256 / 256 / 256) >> 0,
            int(start_time / 256 / 256 / 256 / 256) >> 0,
            self.browser_len,
        )
    
    @staticmethod
    def reg_to_array(a):
        o = [0] * 32
        for i in range(8):
            c = a[i]
            o[4 * i + 3] = (255 & c)
            c >>= 8
            o[4 * i + 2] = (255 & c)
            c >>= 8
            o[4 * i + 1] = (255 & c)
            c >>= 8
            o[4 * i] = (255 & c)
        return o
    
    def compress(self, a):
        f = self.generate_f(a)
        i = self.reg[:]
        for o in range(64):
            c = self.de(i[0], 12) + i[4] + self.de(self.pe(o), o)
            c = (c & 0xFFFFFFFF)
            c = self.de(c, 7)
            s = (c ^ self.de(i[0], 12)) & 0xFFFFFFFF
            
            u = self.he(o, i[0], i[1], i[2])
            u = (u + i[3] + s + f[o + 68]) & 0xFFFFFFFF
            
            b = self.ve(o, i[4], i[5], i[6])
            b = (b + i[7] + c + f[o]) & 0xFFFFFFFF
            
            i[3] = i[2]
            i[2] = self.de(i[1], 9)
            i[1] = i[0]
            i[0] = u
            
            i[7] = i[6]
            i[6] = self.de(i[5], 19)
            i[5] = i[4]
            i[4] = (b ^ self.de(b, 9) ^ self.de(b, 17)) & 0xFFFFFFFF
        
        for l in range(8):
            self.reg[l] = (self.reg[l] ^ i[l]) & 0xFFFFFFFF
    
    @classmethod
    def generate_f(cls, e):
        r = [0] * 132
        
        for t in range(16):
            r[t] = (e[4 * t] << 24) | (e[4 * t + 1] <<
                                       16) | (e[4 * t + 2] << 8) | e[4 * t + 3]
            r[t] &= 0xFFFFFFFF
        
        for n in range(16, 68):
            a = r[n - 16] ^ r[n - 9] ^ cls.de(r[n - 3], 15)
            a = a ^ cls.de(a, 15) ^ cls.de(a, 23)
            r[n] = (a ^ cls.de(r[n - 13], 7) ^ r[n - 6]) & 0xFFFFFFFF
        
        for n in range(68, 132):
            r[n] = (r[n - 68] ^ r[n - 64]) & 0xFFFFFFFF
        
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
            self.chunk.append((size >> 8 * (3 - i)) & 255)
    
    @staticmethod
    def list_4(
            a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int,
            i: int, j: int, k: int, m: int, n: int, o: int, p: int, q: int, r: int,
    ) -> list:
        return [
            44, a, 0, 0, 0, 0, 24, b, n, 0, c, d, 0, 0, 0, 1, 0, 239, e, o, f, g, 0, 0, 0, 0, h, 0, 0, 14, i, j, 0, k, m, 3, p, 1, q, 1, r, 0, 0, 0
        ]
    
    @staticmethod
    def end_check_num(a: list):
        r = 0
        for i in a:
            r ^= i
        return r
    
    @classmethod
    def decode_string(cls, url_string, ):
        decoded = cls.__filter.sub(cls.replace_func, url_string)
        return decoded
    
    @staticmethod
    def replace_func(match):
        return chr(int(match.group(1), 16))
    
    @staticmethod
    def de(e, r):
        r %= 32
        return ((e << r) & 0xFFFFFFFF) | (e >> (32 - r))
    
    @staticmethod
    def pe(e):
        return 2043430169 if 0 <= e < 16 else 2055708042
    
    @staticmethod
    def he(e, r, t, n):
        if 0 <= e < 16:
            return (r ^ t ^ n) & 0xFFFFFFFF
        elif 16 <= e < 64:
            return (r & t | r & n | t & n) & 0xFFFFFFFF
        raise ValueError
    
    @staticmethod
    def ve(e, r, t, n):
        if 0 <= e < 16:
            return (r ^ t ^ n) & 0xFFFFFFFF
        elif 16 <= e < 64:
            return (r & t | ~r & n) & 0xFFFFFFFF
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
    
    def write(self, e, ):
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
    
    def reset(self, ):
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
        r = ""
        for i, j in zip(range(18, -1, -6), (16515072, 258048, 4032, 63)):
            r += cls.__str[s][(n & j) >> i]
        return r
    
    @classmethod
    def generate_result_end(cls, s, e="s4"):
        r = ""
        b = ord(s[120]) << 16
        r += cls.__str[e][(b & 16515072) >> 18]
        r += cls.__str[e][(b & 258048) >> 12]
        r += "=="
        return r
    
    @classmethod
    def generate_result(cls, s, e="s4"):
        r = []
        
        for i in range(0, len(s), 3):
            if i + 2 < len(s):
                n = (
                    (ord(s[i]) << 16)
                    | (ord(s[i + 1]) << 8)
                    | ord(s[i + 2])
                )
            elif i + 1 < len(s):
                n = (ord(s[i]) << 16) | (
                    ord(s[i + 1]) << 8
                )
            else:
                n = ord(s[i]) << 16
            
            for j, k in zip(range(18, -1, -6),
                            (0xFC0000, 0x03F000, 0x0FC0, 0x3F)):
                if j == 6 and i + 1 >= len(s):
                    break
                if j == 0 and i + 2 >= len(s):
                    break
                r.append(cls.__str[e][(n & k) >> j])
        
        r.append("=" * ((4 - len(r) % 4) % 4))
        return "".join(r)
    
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
    
    def generate_method_code(self, method: str = "GET") -> list[int]:
        return self.sm3_to_array(self.sm3_to_array(method + self.__end_string))
    
    def generate_params_code(self, params: str) -> list[int]:
        return self.sm3_to_array(self.sm3_to_array(params + self.__end_string))
    
    @classmethod
    def sm3_to_array(cls, data: Union[str, list]) -> list[int]:
        """
        代码参考: https://github.com/Johnserf-Seed/f2/blob/main/f2/utils/abogus.py
        
        计算请求体的 SM3 哈希值，并将结果转换为整数数组
        Calculate the SM3 hash value of the request body and convert the result to an array of integers
        
        Args:
            data (Union[str, List[int]]): 输入数据 (Input data).
            
        Returns:
            List[int]: 哈希值的整数数组 (Array of integers representing the hash value).
        """
        
        if isinstance(data, str):
            b = data.encode("utf-8")
        else:
            b = bytes(data)  # 将 List[int] 转换为字节数组
        
        # 将字节数组转换为适合 sm3.sm3_hash 函数处理的列表格式
        h = sm3.sm3_hash(func.bytes_to_list(b))
        
        # 将十六进制字符串结果转换为十进制整数列表
        return [int(h[i: i + 2], 16) for i in range(0, len(h), 2)]
    
    @staticmethod
    def rc4_encrypt(plaintext, key):
        s = list(range(256))
        j = 0
        
        for i in range(256):
            j = (j + s[i] + ord(key[i % len(key)])) % 256
            s[i], s[j] = s[j], s[i]
        
        i = 0
        j = 0
        cipher = []
        
        for k in range(len(plaintext)):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            t = (s[i] + s[j]) % 256
            cipher.append(chr(s[t] ^ ord(plaintext[k])))
        
        return ''.join(cipher)
    
    def get_value(self,
                  url_params: Union[dict, str],
                  method="GET",
                  start_time=0,
                  end_time=0,
                  random_num_1=None,
                  random_num_2=None,
                  random_num_3=None,
                  ) -> str:
        string_1 = self.generate_string_1(
            random_num_1,
            random_num_2,
            random_num_3,
        )
        string_2 = self.generate_string_2(urlencode(url_params) if isinstance(
            url_params, dict) else url_params, method, start_time, end_time, )
        string = string_1 + string_2
        return self.generate_result(string, "s4")


class BogusManager:
    """签名管理器 (Signature Manager)"""
    
    @classmethod
    def xb_str_2_endpoint(cls, endpoint: str, user_agent: str) -> str:
        """
        字符串方法生成X-Bogus参数 (Generate X-Bogus parameter using string method)
        
        Args:
            endpoint (str): 端点字符串 (Endpoint string)
            user_agent (str): 用户代理 (User agent)
            
        Returns:
            str: 带X-Bogus的端点 (Endpoint with X-Bogus)
        """
        try:
            final_endpoint = XBogus(user_agent).getXBogus(endpoint)
        except Exception as e:
            raise RuntimeError("生成X-Bogus失败: {0}".format(e))
        
        return final_endpoint[0]
    
    @classmethod
    def xb_model_2_endpoint(cls, base_endpoint: str, params: dict, user_agent: str) -> str:
        """
        字典方法生成X-Bogus参数 (Generate X-Bogus parameter using dictionary method)
        
        Args:
            base_endpoint (str): 基础端点 (Base endpoint)
            params (dict): 参数字典 (Parameters dictionary)
            user_agent (str): 用户代理 (User agent)
            
        Returns:
            str: 带X-Bogus的完整端点 (Complete endpoint with X-Bogus)
        """
        if not isinstance(params, dict):
            raise TypeError("参数必须是字典类型")
        
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        
        try:
            xb_value = XBogus(user_agent).getXBogus(param_str)
        except Exception as e:
            raise RuntimeError("生成X-Bogus失败: {0}".format(e))
        
        # 检查base_endpoint是否已有查询参数 (Check if base_endpoint already has query parameters)
        separator = "&" if "?" in base_endpoint else "?"
        
        final_endpoint = f"{base_endpoint}{separator}{param_str}&X-Bogus={xb_value[1]}"
        
        return final_endpoint
    
    @classmethod
    def ab_model_2_endpoint(cls, params: dict, user_agent: str) -> str:
        """
        字典方法生成A-Bogus参数 (Generate A-Bogus parameter using dictionary method)
        
        Args:
            params (dict): 参数字典 (Parameters dictionary)
            user_agent (str): 用户代理 (User agent)
            
        Returns:
            str: A-Bogus值 (A-Bogus value)
        """
        if not isinstance(params, dict):
            raise TypeError("参数必须是字典类型")
        
        try:
            ab_value = ABogus().get_value(params, )
        except Exception as e:
            raise RuntimeError("生成A-Bogus失败: {0}".format(e))
        
        return quote(ab_value, safe='')


# ==================== 数据模型模块 (Data Model Module) ====================

class BaseRequestModel(BaseModel):
    """基础请求模型 (Base Request Model)"""
    device_platform: str = "webapp"
    aid: str = "6383"
    channel: str = "channel_pc_web"
    pc_client_type: int = 1
    version_code: str = "290100"
    version_name: str = "29.1.0"
    cookie_enabled: str = "true"
    screen_width: int = 1920
    screen_height: int = 1080
    browser_language: str = "zh-CN"
    browser_platform: str = "Win32"
    browser_name: str = "Chrome"
    browser_version: str = "130.0.0.0"
    browser_online: str = "true"
    engine_name: str = "Blink"
    engine_version: str = "130.0.0.0"
    os_name: str = "Windows"
    os_version: str = "10"
    cpu_core_num: int = 12
    device_memory: int = 8
    platform: str = "PC"
    downlink: str = "10"
    effective_type: str = "4g"
    from_user_page: str = "1"
    locate_query: str = "false"
    need_time_list: str = "1"
    pc_libra_divert: str = "Windows"
    publish_video_strategy_type: str = "2"
    round_trip_time: str = "0"
    show_live_replay_strategy: str = "1"
    time_list_query: str = "0"
    whale_cut_token: str = ""
    update_version_code: str = "170400"
    msToken: str = ""
    verifyFp: str = ""
    
    def __init__(self, **data):
        # 自动生成msToken和verifyFp (Auto-generate msToken and verifyFp)
        if not data.get('msToken'):
            data['msToken'] = TokenManager.gen_false_msToken()
        if not data.get('verifyFp'):
            data['verifyFp'] = VerifyFpManager.gen_verify_fp()
        super().__init__(**data)


class PostComments(BaseRequestModel):
    """评论请求模型 (Comment Request Model)"""
    aweme_id: str
    cursor: int = 0
    count: int = 20
    item_type: int = 0
    insert_ids: str = ""
    whale_cut_token: str = ""
    cut_version: int = 1
    rcFT: str = ""


class UserProfile(BaseRequestModel):
    """用户资料请求模型 (User Profile Request Model)"""
    sec_user_id: str


# ==================== 网络请求模块 (Network Request Module) ====================

class BaseCrawler:
    """
    基础爬虫客户端 (Base crawler client)
    """
    
    def __init__(
            self,
            proxies: dict = None,
            max_retries: int = None,
            max_connections: int = None,
            timeout: int = None,
            max_tasks: int = None,
            crawler_headers: dict = None,
    ):
        # 获取配置 (Get configuration)
        config_manager = ConfigManager()
        network_config = config_manager.get_config_value('network', {})
        
        # 设置代理 (Set proxies)
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
        
        # 爬虫请求头 (Crawler request header)
        self.crawler_headers = crawler_headers or config_manager.get_config_value('headers', {})
        
        # 异步的任务数 (Number of asynchronous tasks)
        self._max_tasks = max_tasks or network_config.get('max_tasks', DefaultConfig.DEFAULT_MAX_TASKS)
        self.semaphore = asyncio.Semaphore(self._max_tasks)
        
        # 限制最大连接数 (Limit the maximum number of connections)
        self._max_connections = max_connections or network_config.get('max_connections', DefaultConfig.DEFAULT_MAX_CONNECTIONS)
        self.limits = httpx.Limits(max_connections=self._max_connections)
        
        # 业务逻辑重试次数 (Business logic retry count)
        self._max_retries = max_retries or network_config.get('max_retries', DefaultConfig.DEFAULT_MAX_RETRIES)
        # 底层连接重试次数 (Underlying connection retry count)
        self.atransport = httpx.AsyncHTTPTransport(retries=self._max_retries)
        
        # 超时等待时间 (Timeout waiting time)
        self._timeout = timeout or network_config.get('timeout', DefaultConfig.DEFAULT_TIMEOUT)
        self.timeout = httpx.Timeout(self._timeout)
        
        # 异步客户端 (Asynchronous client)
        # 注意：httpx 使用 mounts 而不是 proxies 参数
        client_kwargs = {
            "headers": self.crawler_headers,
            "timeout": self.timeout,
            "limits": self.limits,
            "transport": self.atransport,
        }
        
        # 如果有代理配置，使用 mounts 参数
        if self.proxies:
            client_kwargs["mounts"] = self.proxies
        
        self.aclient = httpx.AsyncClient(**client_kwargs)
        
        # 设置日志器 (Setup logger)
        self.logger = LoggerManager.setup_logger("BaseCrawler")
    
    async def fetch_response(self, endpoint: str) -> httpx.Response:
        """
        获取数据 (Get data)
        
        Args:
            endpoint (str): 接口地址 (Endpoint URL)
            
        Returns:
            Response: 原始响应对象 (Raw response object)
        """
        return await self.get_fetch_data(endpoint)
    
    async def fetch_get_json(self, endpoint: str) -> dict:
        """
        获取 JSON 数据 (Get JSON data)
        
        Args:
            endpoint (str): 接口地址 (Endpoint URL)
            
        Returns:
            dict: 解析后的JSON数据 (Parsed JSON data)
        """
        response = await self.get_fetch_data(endpoint)
        return self.parse_json(response)
    
    async def fetch_post_json(self, endpoint: str, params: dict = {}, data=None) -> dict:
        """
        获取 JSON 数据 (Post JSON data)
        
        Args:
            endpoint (str): 接口地址 (Endpoint URL)
            params (dict): POST参数 (POST parameters)
            data: POST数据 (POST data)
            
        Returns:
            dict: 解析后的JSON数据 (Parsed JSON data)
        """
        response = await self.post_fetch_data(endpoint, params, data)
        return self.parse_json(response)
    
    def parse_json(self, response: httpx.Response) -> dict:
        """
        解析JSON响应对象 (Parse JSON response object)
        
        Args:
            response (Response): 原始响应对象 (Raw response object)
            
        Returns:
            dict: 解析后的JSON数据 (Parsed JSON data)
        """
        if (
                response is not None
                and isinstance(response, httpx.Response)
                and response.status_code == 200
        ):
            try:
                return response.json()
            except json.JSONDecodeError as e:
                # 尝试使用正则表达式匹配response.text中的json数据
                match = re.search(RegexPatterns.JSON_MATCH, response.text)
                try:
                    return json.loads(match.group())
                except (json.JSONDecodeError, AttributeError) as e:
                    self.logger.error(f"解析 {response.url} 接口 JSON 失败： {e}")
                    raise APIResponseError("解析JSON数据失败")
        
        else:
            if isinstance(response, httpx.Response):
                self.logger.error(f"获取数据失败。状态码: {response.status_code}")
            else:
                self.logger.error(f"无效响应类型。响应类型: {type(response)}")
            
            raise APIResponseError("获取数据失败")
    
    async def get_fetch_data(self, url: str):
        """
        获取GET端点数据 (Get GET endpoint data)
        
        Args:
            url (str): 端点URL (Endpoint URL)
            
        Returns:
            response: 响应内容 (Response content)
        """
        for attempt in range(self._max_retries):
            try:
                self.logger.debug(f"GET请求: {url} (尝试 {attempt + 1}/{self._max_retries})")
                response = await self.aclient.get(url, follow_redirects=True)
                
                if not response.text.strip() or not response.content:
                    error_message = f"第 {attempt + 1} 次响应内容为空, 状态码: {response.status_code}, URL:{response.url}"
                    self.logger.warning(error_message)
                    
                    if attempt == self._max_retries - 1:
                        raise APIRetryExhaustedError("获取端点数据失败, 次数达到上限")
                    
                    await asyncio.sleep(self._timeout)
                    continue
                
                # 记录请求日志 (Log request)
                LoggerManager.log_request(str(response.url), "GET", response.status_code)
                
                response.raise_for_status()
                return response
            
            except httpx.RequestError as e:
                error_msg = f"连接端点失败，检查网络环境或代理：{url} 代理：{self.proxies}"
                self.logger.error(error_msg)
                raise APIConnectionError(error_msg, {"url": url, "proxies": self.proxies})
            
            except httpx.HTTPStatusError as http_error:
                self.handle_http_status_error(http_error, url, attempt + 1)
            
            except APIError as e:
                e.display_error()
                raise
    
    async def post_fetch_data(self, url: str, params: dict = {}, data=None):
        """
        获取POST端点数据 (Get POST endpoint data)
        
        Args:
            url (str): 端点URL (Endpoint URL)
            params (dict): POST请求参数 (POST request parameters)
            data: POST数据 (POST data)
            
        Returns:
            response: 响应内容 (Response content)
        """
        for attempt in range(self._max_retries):
            try:
                self.logger.debug(f"POST请求: {url} (尝试 {attempt + 1}/{self._max_retries})")
                response = await self.aclient.post(
                    url,
                    json=None if not params else dict(params),
                    data=None if not data else data,
                    follow_redirects=True
                )
                
                if not response.text.strip() or not response.content:
                    error_message = f"第 {attempt + 1} 次响应内容为空, 状态码: {response.status_code}, URL:{response.url}"
                    self.logger.warning(error_message)
                    
                    if attempt == self._max_retries - 1:
                        raise APIRetryExhaustedError("获取端点数据失败, 次数达到上限")
                    
                    await asyncio.sleep(self._timeout)
                    continue
                
                # 记录请求日志 (Log request)
                LoggerManager.log_request(str(response.url), "POST", response.status_code)
                
                response.raise_for_status()
                return response
            
            except httpx.RequestError as e:
                error_msg = f"连接端点失败，检查网络环境或代理：{url} 代理：{self.proxies}"
                self.logger.error(error_msg)
                raise APIConnectionError(error_msg, {"url": url, "proxies": self.proxies})
            
            except httpx.HTTPStatusError as http_error:
                self.handle_http_status_error(http_error, url, attempt + 1)
            
            except APIError as e:
                e.display_error()
                raise
    
    def handle_http_status_error(self, http_error, url: str, attempt):
        """
        处理HTTP状态错误 (Handle HTTP status error)
        
        Args:
            http_error: HTTP状态错误 (HTTP status error)
            url: 端点URL (Endpoint URL)
            attempt: 尝试次数 (Number of attempts)
        """
        response = getattr(http_error, "response", None)
        status_code = getattr(response, "status_code", None)
        
        if response is None or status_code is None:
            self.logger.error(f"HTTP状态错误: {http_error}, URL: {url}, 尝试次数: {attempt}")
            raise APIResponseError(f"处理HTTP错误时遇到意外情况: {http_error}")
        
        if status_code == 302:
            pass
        elif status_code == 404:
            raise APINotFoundError(f"HTTP Status Code {status_code}")
        elif status_code == 503:
            raise APIUnavailableError(f"HTTP Status Code {status_code}")
        elif status_code == 408:
            raise APITimeoutError(f"HTTP Status Code {status_code}")
        elif status_code == 401:
            raise APIUnauthorizedError(f"HTTP Status Code {status_code}")
        elif status_code == 429:
            raise APIRateLimitError(f"HTTP Status Code {status_code}")
        else:
            self.logger.error(f"HTTP状态错误: {status_code}, URL: {url}, 尝试次数: {attempt}")
            raise APIResponseError(f"HTTP状态错误: {status_code}")
    
    async def close(self):
        await self.aclient.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclient.aclose()


# ==================== 抖音爬虫模块 (Douyin Crawler Module) ====================

class DouyinWebCrawler:
    """抖音网页爬虫类 (Douyin Web Crawler Class)"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.logger = LoggerManager.setup_logger("DouyinWebCrawler")
    
    def get_douyin_headers(self):
        """
        获取抖音请求头配置 (Get Douyin request headers configuration)
        
        Returns:
            dict: 包含headers和proxies的配置字典 (Configuration dictionary containing headers and proxies)
        """
        headers_config = self.config_manager.get_config_value('headers', {})
        network_config = self.config_manager.get_config_value('network', {})
        
        # 处理代理配置 (Handle proxy configuration)
        proxy_config = network_config.get('proxies', {})
        proxies = {}
        if proxy_config.get('http'):
            proxies["http://"] = proxy_config['http']
        if proxy_config.get('https'):
            proxies["https://"] = proxy_config['https']
        
        kwargs = {
            "headers": headers_config,
            "proxies": proxies if proxies else None,
        }
        return kwargs
    
    async def fetch_video_comments(self, aweme_id: str, cursor: int = 0, count: int = 20):
        """
        获取指定视频的评论数据 (Get comment data for specified video)
        
        Args:
            aweme_id (str): 视频ID (Video ID)
            cursor (int): 分页游标 (Pagination cursor)
            count (int): 每页数量 (Items per page)
            
        Returns:
            dict: 评论数据 (Comment data)
        """
        kwargs = self.get_douyin_headers()
        base_crawler = BaseCrawler(proxies=kwargs["proxies"], crawler_headers=kwargs["headers"])
        
        async with base_crawler as crawler:
            params = PostComments(aweme_id=aweme_id, cursor=cursor, count=count)
            
            # 获取API端点 (Get API endpoint)
            api_domain = self.config_manager.get_config_value('api.douyin_domain', APIEndpoints.DOUYIN_DOMAIN)
            comment_endpoint = self.config_manager.get_config_value('api.endpoints.post_comment', '/aweme/v1/web/comment/list/')
            base_endpoint = api_domain + comment_endpoint
            
            endpoint = BogusManager.xb_model_2_endpoint(
                base_endpoint, params.dict(), kwargs["headers"]["User-Agent"]
            )
            
            self.logger.info(f"获取视频评论: aweme_id={aweme_id}, cursor={cursor}, count={count}")
            response = await crawler.fetch_get_json(endpoint)
            
        return response
    
    async def fetch_user_profile(self, sec_user_id: str):
        """
        获取用户资料信息 (Get user profile information)
        
        Args:
            sec_user_id (str): 用户安全ID (User secure ID)
            
        Returns:
            dict: 用户资料数据 (User profile data)
        """
        kwargs = self.get_douyin_headers()
        base_crawler = BaseCrawler(proxies=kwargs["proxies"], crawler_headers=kwargs["headers"])
        
        async with base_crawler as crawler:
            params = UserProfile(sec_user_id=sec_user_id)
            
            # 获取API端点 (Get API endpoint)
            api_domain = self.config_manager.get_config_value('api.douyin_domain', APIEndpoints.DOUYIN_DOMAIN)
            user_endpoint = self.config_manager.get_config_value('api.endpoints.user_detail', '/aweme/v1/web/user/profile/other/')
            base_endpoint = api_domain + user_endpoint
            
            endpoint = BogusManager.xb_model_2_endpoint(
                base_endpoint, params.dict(), kwargs["headers"]["User-Agent"]
            )
            
            self.logger.info(f"获取用户资料: sec_user_id={sec_user_id}")
            response = await crawler.fetch_get_json(endpoint)
            
        return response


# ==================== 数据处理模块 (Data Processing Module) ====================

def simplify_comment_result(result: dict) -> dict:
    """
    简化评论API响应为更易读的格式 (Simplify comment API response to a more readable format)
    
    Args:
        result (dict): 原始API响应 (Raw API response)
        
    Returns:
        dict: 简化后的评论数据 (Simplified comment data)
    """
    # UTC+8 时区
    utc8_tz = datetime.timezone(datetime.timedelta(hours=TimezoneConstants.UTC8_OFFSET_HOURS))
    
    extracted_comments = []
    # 确保result和result['comments']存在且可迭代 (Ensure result and result['comments'] exist and are iterable)
    if result and isinstance(result.get('comments'), list):
        for comment in result.get("comments", []):
            creation_time = datetime.datetime.fromtimestamp(comment["create_time"], tz=utc8_tz)
            
            # 使用reply_comment_total而不是replies数组 (Use reply_comment_total instead of the replies array)
            reply_comment_total = len(comment.get("reply_comment", [])) if isinstance(comment.get("reply_comment"), list) else 0
            
            images = []
            if comment.get("image_list") and isinstance(comment.get("image_list"), list):
                for image in comment.get("image_list"):
                    images.append(image.get("origin_url", {}).get("url_list", []))
            
            extracted_comments.append({
                "comment_id": comment.get("cid"),  # 添加 comment_id 字段
                "creation_time_utc8": creation_time.strftime(TimezoneConstants.DATETIME_FORMAT),
                "sec_user_id": comment.get("user", {}).get("sec_uid"),
                "nickname": comment.get("user", {}).get("nickname"),  # 添加用户昵称字段
                "ip_location": comment.get("ip_label"),  # 添加ip地址
                "content": comment.get("text"),
                "digg_count": comment.get("digg_count"),
                "reply_comment_total": reply_comment_total,  # 用 reply_comment_total 替代 replies 数组
                "images": images
            })
    
    simplified_dict = {
        "pagination_info": {
            "total_comments": result.get("total"),
            "next_cursor": result.get("cursor"),
            "has_more": bool(result.get("has_more"))
        },
        "comments": extracted_comments
    }
    
    return simplified_dict


def save_json_file(data: dict, filename: str, indent: int = 2, ensure_ascii: bool = False):
    """
    保存数据到JSON文件 (Save data to JSON file)
    
    Args:
        data (dict): 要保存的数据 (Data to save)
        filename (str): 文件名 (Filename)
        indent (int): JSON缩进 (JSON indentation)
        ensure_ascii (bool): 是否确保ASCII编码 (Whether to ensure ASCII encoding)
    """
    logger = LoggerManager.setup_logger("DataProcessor")
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
        logger.info(f"数据已保存到文件: {filename}")
    except Exception as e:
        logger.error(f"保存文件失败: {filename}, 错误: {e}")
        raise


# ==================== 验证模块 (Validation Module) ====================

def validate_aweme_id(aweme_id: str) -> bool:
    """
    验证aweme_id格式 (Validate aweme_id format)
    
    Args:
        aweme_id (str): 视频ID (Video ID)
        
    Returns:
        bool: 验证结果 (Validation result)
    """
    if not aweme_id or not isinstance(aweme_id, str):
        return False
    
    # 基本检查 - aweme_id通常是19位数字 (Basic check - aweme_id is usually 19 digits)
    return re.match(RegexPatterns.AWEME_ID_PATTERN, aweme_id) is not None


def validate_sec_user_id(sec_user_id: str) -> bool:
    """
    验证sec_user_id格式 (Validate sec_user_id format)
    
    Args:
        sec_user_id (str): 用户安全ID (User secure ID)
        
    Returns:
        bool: 验证结果 (Validation result)
    """
    if not sec_user_id or not isinstance(sec_user_id, str):
        return False
    
    # 基本检查 - sec_user_id通常以MS4wLjAB开头且有一定长度 (Basic check - sec_user_id usually starts with MS4wLjAB and has a certain length)
    config_manager = ConfigManager()
    min_length = config_manager.get_config_value('validation.sec_user_id.min_length', 30)
    
    if len(sec_user_id) < min_length:
        return False
    
    pattern = config_manager.get_config_value('validation.sec_user_id.pattern', RegexPatterns.SEC_USER_ID_PATTERN)
    return re.match(pattern, sec_user_id) is not None


# ==================== 工具函数模块 (Utility Functions Module) ====================

def setup_environment():
    """
    设置环境 (Setup environment)
    
    Returns:
        tuple: (config_manager, logger) 配置管理器和日志器 (Configuration manager and logger)
    """
    # 初始化配置管理器 (Initialize configuration manager)
    config_manager = ConfigManager()
    
    # 设置日志器 (Setup logger)
    logger = LoggerManager.setup_logger()
    
    # 验证配置 (Validate configuration)
    if not config_manager.validate_config():
        logger.warning("配置验证失败，使用默认配置")
    
    logger.info("环境设置完成")
    return config_manager, logger


def get_current_timestamp() -> str:
    """
    获取当前时间戳字符串 (Get current timestamp string)
    
    Returns:
        str: 格式化的时间戳 (Formatted timestamp)
    """
    utc8_tz = datetime.timezone(datetime.timedelta(hours=TimezoneConstants.UTC8_OFFSET_HOURS))
    now = datetime.datetime.now(tz=utc8_tz)
    return now.strftime(TimezoneConstants.DATETIME_FORMAT)


def create_output_filename(base_name: str, extension: str = "json", add_timestamp: bool = False) -> str:
    """
    创建输出文件名 (Create output filename)
    
    Args:
        base_name (str): 基础文件名 (Base filename)
        extension (str): 文件扩展名 (File extension)
        add_timestamp (bool): 是否添加时间戳 (Whether to add timestamp)
        
    Returns:
        str: 完整的文件名 (Complete filename)
    """
    if add_timestamp:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base_name}_{timestamp}.{extension}"
    else:
        return f"{base_name}.{extension}"


# ==================== 导出接口 (Export Interface) ====================

__all__ = [
    # 配置管理 (Configuration Management)
    'ConfigManager',
    
    # 日志系统 (Logging System)
    'LoggerManager',
    
    # 异常处理 (Exception Handling)
    'APIError', 'APIConnectionError', 'APIResponseError', 'APITimeoutError',
    'APIUnavailableError', 'APIUnauthorizedError', 'APINotFoundError',
    'APIRateLimitError', 'APIRetryExhaustedError',
    
    # Token管理 (Token Management)
    'TokenManager', 'VerifyFpManager',
    
    # 签名算法 (Signature Algorithms)
    'XBogus', 'ABogus', 'BogusManager',
    
    # 数据模型 (Data Models)
    'BaseRequestModel', 'PostComments', 'UserProfile',
    
    # 网络请求 (Network Requests)
    'BaseCrawler',
    
    # 抖音爬虫 (Douyin Crawler)
    'DouyinWebCrawler',
    
    # 数据处理 (Data Processing)
    'simplify_comment_result', 'save_json_file',
    
    # 验证函数 (Validation Functions)
    'validate_aweme_id', 'validate_sec_user_id',
    
    # 工具函数 (Utility Functions)
    'setup_environment', 'get_current_timestamp', 'create_output_filename',
]