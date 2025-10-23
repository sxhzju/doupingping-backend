#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抖音爬虫常量定义模块
Constants module for Douyin crawler

所有配置已硬编码到此文件中
"""

# ==================== Cookie配置 (Cookie Configuration) ====================
DOUYIN_COOKIE = "enter_pc_once=1; UIFID_TEMP=30ff7b230d01f3ed4fd5546706fc508e0725b8a99e0ba4197a991a959864baf0c2b6ee65e651b24b04b65361253a72930baacb599ba60e80717e48c4b64eea230f7466e6ab8914083e966461e0e47f46f035734fa99bfe2f4c02ad1d66dded58d97c15241b55d8b69643ffa152dddbbd; s_v_web_id=verify_mg57aqn9_kgoRuDBt_ygpr_4L9z_8TaQ_uw9fC4FbipAw; hevc_supported=true; dy_swidth=2048; dy_sheight=1152; fpk1=U2FsdGVkX19Zf5Y9a5Z6xm/Z2XEPV4W7UPW/G9hIabS1YD1ATq14PE0guJovnD8q9CMKAGxqZFBtFfz/FoMGFg==; fpk2=7ceed19ee5ebdbf792f56329591ffc53; xgplayer_user_id=332989463482; passport_csrf_token=257b54f6b42856d7f2d79777699be4c2; passport_csrf_token_default=257b54f6b42856d7f2d79777699be4c2; __security_mc_1_s_sdk_crypt_sdk=60fdab15-4cc7-b40b; bd_ticket_guard_client_web_domain=2; d_ticket=98dfef85ffb46558bdef5b74c17c410d80bd0; n_mh=rZbLvuXyRyiN7VCxvrqeeK_L419A7HUwPpGO0twgduE; passport_auth_status=2dce8d3d7372dc854af63159c690e9c1%2C; passport_auth_status_ss=2dce8d3d7372dc854af63159c690e9c1%2C; is_staff_user=false; __security_mc_1_s_sdk_cert_key=6037c304-45e7-b575; __security_server_data_status=1; UIFID=30ff7b230d01f3ed4fd5546706fc508e0725b8a99e0ba4197a991a959864baf0c2b6ee65e651b24b04b65361253a72930baacb599ba60e80717e48c4b64eea23f4e261dee374115c21f380ffa1130bc4f934694441d1fa0421b8787e44490cf36903d5fe5376f56fbf346d23c0b5ca0f7ea7772253ab9cf5317c7f49a1251c07ddf55b465fd466d5cde7190afe27832bee6bcefe1c8e8dff88ebd776fbecd654d541ee0c808c6fec3d54fd784f15861a; SelfTabRedDotControl=%5B%5D; is_dash_user=1; live_use_vvc=%22false%22; xgplayer_device_id=88360542820; download_guide=%220%2F%2F1%22; SEARCH_RESULT_LIST_TYPE=%22single%22; __druidClientInfo=JTdCJTIyY2xpZW50V2lkdGglMjIlM0E0NDYlMkMlMjJjbGllbnRIZWlnaHQlMjIlM0E4NzglMkMlMjJ3aWR0aCUyMiUzQTQ0NiUyQyUyMmhlaWdodCUyMiUzQTg3OCUyQyUyMmRldmljZVBpeGVsUmF0aW8lMjIlM0ExLjI1JTJDJTIydXNlckFnZW50JTIyJTNBJTIyTW96aWxsYSUyRjUuMCUyMChXaW5kb3dzJTIwTlQlMjAxMC4wJTNCJTIwV2luNjQlM0IlMjB4NjQpJTIwQXBwbGVXZWJLaXQlMkY1MzcuMzYlMjAoS0hUTUwlMkMlMjBsaWtlJTIwR2Vja28pJTIwQ2hyb21lJTJGMTQxLjAuMC4wJTIwU2FmYXJpJTJGNTM3LjM2JTIwRWRnJTJGMTQxLjAuMC4wJTIyJTdE; passport_mfa_token=CjUdfkbDCgppjiMmg0eC0IJsNm5K3Dm9pQiTEPQB52oLlinjJwAUnFFAQtMkCu43kk3b7CTANxpKCjwAAAAAAAAAAAAAT4%2B0hI8h2X%2FNfmFUpJNlq0U0opEHk1K896%2Bq9OU%2F3%2F1WT1ImFccrNuUObfmqa00Y%2FWsQnor%2BDRj2sdFsIAIiAQOtHxXi; _bd_ticket_crypt_doamin=2; publish_badge_show_info=%220%2C0%2C0%2C1759760299993%22; FOLLOW_LIVE_POINT_INFO=%22MS4wLjABAAAANtsQjkSYWEdApIe1ypmMPTZTdVKmpjZiFVruqCdGaus%2F1759852800000%2F0%2F0%2F1759819955636%22; FOLLOW_NUMBER_YELLOW_POINT_INFO=%22MS4wLjABAAAANtsQjkSYWEdApIe1ypmMPTZTdVKmpjZiFVruqCdGaus%2F1759852800000%2F0%2F1759819355636%2F0%22; shareRecommendGuideTagCount=4; volume_info=%7B%22isUserMute%22%3Afalse%2C%22isMute%22%3Afalse%2C%22volume%22%3A0.3%7D; douyin.com; device_web_cpu_core=32; device_web_memory_size=8; architecture=amd64; strategyABtestKey=%221759985531.168%22; WallpaperGuide=%7B%22showTime%22%3A0%2C%22closeTime%22%3A0%2C%22showCount%22%3A0%2C%22cursor1%22%3A134%2C%22cursor2%22%3A44%2C%22hoverTime%22%3A1759155464817%7D; __ac_nonce=068e747e9000dfe4a5d84; __ac_signature=_02B4Z6wo00f016iASNgAAIDC0mm8P0XZQLuooExAAILP74; stream_recommend_feed_params=%22%7B%5C%22cookie_enabled%5C%22%3Atrue%2C%5C%22screen_width%5C%22%3A2048%2C%5C%22screen_height%5C%22%3A1152%2C%5C%22browser_online%5C%22%3Atrue%2C%5C%22cpu_core_num%5C%22%3A32%2C%5C%22device_memory%5C%22%3A8%2C%5C%22downlink%5C%22%3A10%2C%5C%22effective_type%5C%22%3A%5C%224g%5C%22%2C%5C%22round_trip_time%5C%22%3A50%7D%22; xg_device_score=7.939512605042016; passport_assist_user=Cj1Ir0Xw4lvpv5NhxMfSGYgpMX9EuMBASYvCg2BsuhN2kf5GSvqSNfaLNnz4zzaStO4r7u0NO15hiymw7ImrGkoKPAAAAAAAAAAAAABPktbq-dwSMsHd3HYIx-VML__vh3SU4djgdxtk2yMxKwPPItTwClVezB14EnNQClAKfxCkrP4NGImv1lQgASIBA8iZ4GY%3D; sid_guard=11e496d5b59eadafcc7b729921474b91%7C1759987705%7C5184000%7CMon%2C+08-Dec-2025+05%3A28%3A25+GMT; uid_tt=78d9ff3dade671c84c96de381e1e69a9; uid_tt_ss=78d9ff3dade671c84c96de381e1e69a9; sid_tt=11e496d5b59eadafcc7b729921474b91; sessionid=11e496d5b59eadafcc7b729921474b91; sessionid_ss=11e496d5b59eadafcc7b729921474b91; sid_ucp_v1=1.0.0-KDk0MDc0MTUxMmFmMmY1ZDBmMmRmOGY4ODdkZTQ5MjAzM2MyZTY5ZjMKHwidlv3xmgMQ-Y-dxwYY7zEgDDC2rfrhBTgFQPsHSAQaAmxxIiAxMWU0OTZkNWI1OWVhZGFmY2M3YjcyOTkyMTQ3NGI5MQ; ssid_ucp_v1=1.0.0-KDk0MDc0MTUxMmFmMmY1ZDBmMmRmOGY4ODdkZTQ5MjAzM2MyZTY5ZjMKHwidlv3xmgMQ-Y-dxwYY7zEgDDC2rfrhBTgFQPsHSAQaAmxxIiAxMWU0OTZkNWI1OWVhZGFmY2M3YjcyOTkyMTQ3NGI5MQ; login_time=1759987705098; __security_mc_1_s_sdk_sign_data_key_web_protect=8b180b1d-4cd6-b00b; _bd_ticket_crypt_cookie=b800cdd1451b806e44db7e11886bdf1f; bd_ticket_guard_client_data=eyJiZC10aWNrZXQtZ3VhcmQtdmVyc2lvbiI6MiwiYmQtdGlja2V0LWd1YXJkLWl0ZXJhdGlvbi12ZXJzaW9uIjoxLCJiZC10aWNrZXQtZ3VhcmQtcmVlLXB1YmxpYy1rZXkiOiJCQmptMXZERkVCUmlPMEMvV0lDN1ltM0VIZDJTTThFbGZlTnJkcDV6QXFjQlE5WEI3STN4emlVdllHRUs4ZjFibFZ3Um9DY1dFU0F3OU90NnRTWWdlTHc9IiwiYmQtdGlja2V0LWd1YXJkLXdlYi12ZXJzaW9uIjoyfQ%3D%3D; home_can_add_dy_2_desktop=%221%22; ttwid=1%7Cxm-jRBUSuMnlqfRjc15ZcDvRH3PeaSgx4RXFIo9WfM8%7C1759987712%7C7e6afa2ac4a7f882e747b559b2e51a031d756f8e2611b0a180a6a10707fc5d7c; odin_tt=89732f374811be8ec41a10b8eed4e052bc21d059d2c8aac67748fcfad56a25676a44dcd62a2fa3bee578b8a9891aaa0a23c490fb3b51219514f0e4f5a4320112; biz_trace_id=6c7dc112; session_tlb_tag=sttt%7C16%7CEeSW1bWera_Me3KZIUdLkf_________QE7IrUaR1qiLC9WfaGErjqHV1Ha32825wLEv-WhU8LEc%3D; playRecommendGuideTagCount=6; totalRecommendGuideTagCount=35; bd_ticket_guard_client_data_v2=eyJyZWVfcHVibGljX2tleSI6IkJCam0xdkRGRUJSaU8wQy9XSUM3WW0zRUhkMlNNOEVsZmVOcmRwNXpBcWNCUTlYQjdJM3h6aVV2WUdFSzhmMWJsVndSb0NjV0VTQXc5T3Q2dFNZZ2VMdz0iLCJ0c19zaWduIjoidHMuMi5hNTc5YzEwODRlZjkwNTFiYWI0OTZkODNmN2VjMjMxM2I0NjY5MjNmN2ZjYmY5ZmYzYmVhNDg3MTZlZGRhYmRhYzRmYmU4N2QyMzE5Y2YwNTMxODYyNGNlZGExNDkxMWNhNDA2ZGVkYmViZWRkYjJlMzBmY2U4ZDRmYTAyNTc1ZCIsInJlcV9jb250ZW50Ijoic2VjX3RzIiwicmVxX3NpZ24iOiJTMmVBTnlKN0ZhcXdBTU1sNC9QYTljdUNoSXk5UzlZaGJFd2hQMWZLU0ZFPSIsInNlY190cyI6IiMrS29Kb3o0V0V0WFlQaGJKKzc0NUVjakRSY0xaYWk1UkFnWmg4aVVOQTlEaU9OQUhLU09CK081d1ZZT1UifQ%3D%3D; stream_player_status_params=%22%7B%5C%22is_auto_play%5C%22%3A0%2C%5C%22is_full_screen%5C%22%3A0%2C%5C%22is_full_webscreen%5C%22%3A0%2C%5C%22is_mute%5C%22%3A0%2C%5C%22is_speed%5C%22%3A1%2C%5C%22is_visible%5C%22%3A1%7D%22; IsDouyinActive=true"

# ==================== 网络配置 (Network Configuration) ====================
class NetworkConfig:
    """网络配置类"""
    # 超时设置 (Timeout Settings)
    TIMEOUT = 30
    
    # 重试设置 (Retry Settings)
    MAX_RETRIES = 3
    
    # 连接池设置 (Connection Pool Settings)
    MAX_CONNECTIONS = 50
    MAX_KEEPALIVE_CONNECTIONS = 10
    
    # 并发设置 (Concurrency Settings)
    MAX_TASKS = 50
    
    # 代理设置 (Proxy Settings) - 如果需要使用代理，请修改为实际代理地址
    HTTP_PROXY = ""  # 例如: "http://127.0.0.1:8080"
    HTTPS_PROXY = ""  # 例如: "https://127.0.0.1:8080"


# ==================== 请求头配置 (Request Headers Configuration) ====================
class HeadersConfig:
    """请求头配置类"""
    # 基础请求头 (Basic Headers)
    ACCEPT_LANGUAGE = "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
    REFERER = "https://www.douyin.com/"
    ACCEPT = "application/json, text/plain, */*"
    ACCEPT_ENCODING = "gzip, deflate, br"
    CONNECTION = "keep-alive"
    
    @classmethod
    def get_headers(cls):
        """获取完整的请求头字典"""
        return {
            "Accept-Language": cls.ACCEPT_LANGUAGE,
            "User-Agent": cls.USER_AGENT,
            "Referer": cls.REFERER,
            "Accept": cls.ACCEPT,
            "Accept-Encoding": cls.ACCEPT_ENCODING,
            "Connection": cls.CONNECTION,
            "Cookie": DOUYIN_COOKIE,
        }


# ==================== 设备信息配置 (Device Information Configuration) ====================
class DeviceConfig:
    """设备信息配置类"""
    # 基础设备信息 (Basic Device Information)
    DEVICE_PLATFORM = "webapp"
    AID = "6383"
    CHANNEL = "channel_pc_web"
    PC_CLIENT_TYPE = 1
    VERSION_CODE = "290100"
    VERSION_NAME = "29.1.0"
    UPDATE_VERSION_CODE = "170400"
    
    # 浏览器信息 (Browser Information)
    COOKIE_ENABLED = "true"
    SCREEN_WIDTH = 1920
    SCREEN_HEIGHT = 1080
    BROWSER_LANGUAGE = "zh-CN"
    BROWSER_PLATFORM = "Win32"
    BROWSER_NAME = "Chrome"
    BROWSER_VERSION = "130.0.0.0"
    BROWSER_ONLINE = "true"
    ENGINE_NAME = "Blink"
    ENGINE_VERSION = "130.0.0.0"
    
    # 系统信息 (System Information)
    OS_NAME = "Windows"
    OS_VERSION = "10"
    CPU_CORE_NUM = 12
    DEVICE_MEMORY = 8
    PLATFORM = "PC"
    
    # 网络信息 (Network Information)
    DOWNLINK = "10"
    EFFECTIVE_TYPE = "4g"
    ROUND_TRIP_TIME = "0"
    
    # 其他参数 (Other Parameters)
    FROM_USER_PAGE = "1"
    LOCATE_QUERY = "false"
    NEED_TIME_LIST = "1"
    PC_LIBRA_DIVERT = "Windows"
    PUBLISH_VIDEO_STRATEGY_TYPE = "2"
    SHOW_LIVE_REPLAY_STRATEGY = "1"
    TIME_LIST_QUERY = "0"
    WHALE_CUT_TOKEN = ""
    
    @classmethod
    def get_device_info(cls):
        """获取完整的设备信息字典"""
        return {
            "device_platform": cls.DEVICE_PLATFORM,
            "aid": cls.AID,
            "channel": cls.CHANNEL,
            "pc_client_type": cls.PC_CLIENT_TYPE,
            "version_code": cls.VERSION_CODE,
            "version_name": cls.VERSION_NAME,
            "cookie_enabled": cls.COOKIE_ENABLED,
            "screen_width": cls.SCREEN_WIDTH,
            "screen_height": cls.SCREEN_HEIGHT,
            "browser_language": cls.BROWSER_LANGUAGE,
            "browser_platform": cls.BROWSER_PLATFORM,
            "browser_name": cls.BROWSER_NAME,
            "browser_version": cls.BROWSER_VERSION,
            "browser_online": cls.BROWSER_ONLINE,
            "engine_name": cls.ENGINE_NAME,
            "engine_version": cls.ENGINE_VERSION,
            "os_name": cls.OS_NAME,
            "os_version": cls.OS_VERSION,
            "cpu_core_num": cls.CPU_CORE_NUM,
            "device_memory": cls.DEVICE_MEMORY,
            "platform": cls.PLATFORM,
            "downlink": cls.DOWNLINK,
            "effective_type": cls.EFFECTIVE_TYPE,
            "from_user_page": cls.FROM_USER_PAGE,
            "locate_query": cls.LOCATE_QUERY,
            "need_time_list": cls.NEED_TIME_LIST,
            "pc_libra_divert": cls.PC_LIBRA_DIVERT,
            "publish_video_strategy_type": cls.PUBLISH_VIDEO_STRATEGY_TYPE,
            "round_trip_time": cls.ROUND_TRIP_TIME,
            "show_live_replay_strategy": cls.SHOW_LIVE_REPLAY_STRATEGY,
            "time_list_query": cls.TIME_LIST_QUERY,
            "whale_cut_token": cls.WHALE_CUT_TOKEN,
            "update_version_code": cls.UPDATE_VERSION_CODE,
        }


# ==================== API端点常量 (API Endpoints) ====================
class APIEndpoints:
    """API端点常量类"""
    # 基础域名 (Base Domains)
    DOUYIN_DOMAIN = "https://www.douyin.com"
    IESDOUYIN_DOMAIN = "https://www.iesdouyin.com"
    LIVE_DOMAIN = "https://live.douyin.com"
    LIVE_DOMAIN2 = "https://webcast.amemv.com"
    SSO_DOMAIN = "https://sso.douyin.com"
    WEBCAST_WSS_DOMAIN = "wss://webcast5-ws-web-lf.douyin.com"
    
    # 具体端点 (Specific Endpoints)
    POST_COMMENT = f"{DOUYIN_DOMAIN}/aweme/v1/web/comment/list/"
    USER_DETAIL = f"{DOUYIN_DOMAIN}/aweme/v1/web/user/profile/other/"
    MS_TOKEN_URL = "https://mssdk.bytedance.com/web/report"
    TTWID_URL = "https://ttwid.bytedance.com/ttwid/union/register/"


# ==================== 分页配置 (Pagination Configuration) ====================
class PaginationConfig:
    """分页配置类"""
    DEFAULT_CURSOR = 0
    DEFAULT_COUNT = 20
    MAX_COUNT = 100


# ==================== 日志配置 (Logging Configuration) ====================
class LoggingConfig:
    """日志配置类"""
    # 日志级别 (Log Level)
    LEVEL = "INFO"  # 可选: DEBUG, INFO, WARNING, ERROR, CRITICAL
    
    # 日志目录 (Log Directory)
    LOG_DIR = "logs"
    
    # 日志格式 (Log Format)
    FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s"
    
    # 日志轮转配置 (Log Rotation Configuration)
    MAX_BYTES = 10485760  # 10MB
    BACKUP_COUNT = 5
    
    # 控制台输出 (Console Output)
    CONSOLE_OUTPUT = True
    CONSOLE_LEVEL = "WARNING"


# ==================== Token生成配置 (Token Generation Configuration) ====================
class TokenConfig:
    """Token生成配置类"""
    # msToken配置 (msToken Configuration)
    MS_TOKEN_MAGIC = 538969122
    MS_TOKEN_VERSION = 1
    MS_TOKEN_DATA_TYPE = 8
    MS_TOKEN_BASE_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    MS_TOKEN_LENGTH = 126
    MS_TOKEN_USER_AGENT = "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47"
    
    # verifyFp配置 (verifyFp Configuration)
    VERIFY_FP_BASE_STR = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    VERIFY_FP_PREFIX = "verify_"
    
    # ttwid配置 (ttwid Configuration)
    TTWID_DATA = '{"region":"cn","aid":1768,"needFid":false,"service":"www.ixigua.com","migrate_info":{"ticket":"","source":"node"},"cbUrlProtocol":"https","union":true}'


# ==================== 签名算法配置 (Signature Algorithm Configuration) ====================
class SignatureConfig:
    """签名算法配置类"""
    # XBogus配置 (XBogus Configuration)
    XBOGUS_CHARACTER = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe="
    XBOGUS_UA_KEY = b"\x00\x01\x0c"
    
    # ABogus配置 (ABogus Configuration)
    ABOGUS_ARGUMENTS = [0, 1, 14]
    ABOGUS_UA_KEY = "\u0000\u0001\u000e"
    ABOGUS_END_STRING = "cus"
    ABOGUS_VERSION = [1, 0, 1, 5]
    ABOGUS_BROWSER = "1536|742|1536|864|0|0|0|0|1536|864|1536|864|1536|742|24|24|MacIntel"
    ABOGUS_REG = [1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214]
    ABOGUS_STR_MAPS = {
        "s0": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        "s1": "Dkdpgh4ZKsQB80/Mfvw36XI1R25+WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
        "s2": "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
        "s3": "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzKFjJnry79HbGDaStCe",
        "s4": "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe",
    }


# ==================== 输出配置 (Output Configuration) ====================
class OutputConfig:
    """输出配置类"""
    # 文件输出配置 (File Output Configuration)
    SAVE_ORIGINAL = True
    SAVE_SIMPLIFIED = True
    
    # 文件名配置 (File Name Configuration)
    COMMENT_ORIGINAL_FILE = "comment_original.json"
    COMMENT_SIMPLIFIED_FILE = "comment_simplified.json"
    USER_ORIGINAL_FILE = "user_original.json"
    USER_SIMPLIFIED_FILE = "user_simplified.json"
    VIDEO_ORIGINAL_FILE = "video_original.json"
    VIDEO_SIMPLIFIED_FILE = "video_simplified.json"
    
    # 输出格式配置 (Output Format Configuration)
    INDENT = 2
    ENSURE_ASCII = False


# ==================== 错误处理配置 (Error Handling Configuration) ====================
class ErrorHandlingConfig:
    """错误处理配置类"""
    # 重试配置 (Retry Configuration)
    RETRY_ON_ERRORS = [408, 429, 503]  # HTTP状态码
    RETRY_DELAY = 1  # 秒
    EXPONENTIAL_BACKOFF = True
    MAX_RETRY_DELAY = 60  # 秒
    
    # 错误日志配置 (Error Logging Configuration)
    LOG_ERRORS = True
    LOG_STACK_TRACE = True


# ==================== 验证配置 (Validation Configuration) ====================
class ValidationConfig:
    """验证配置类"""
    # sec_user_id验证 (sec_user_id Validation)
    SEC_USER_ID_MIN_LENGTH = 30
    SEC_USER_ID_PATTERN = r"^MS4wLjAB[A-Za-z0-9+/=_-]+$"
    
    # aweme_id验证 (aweme_id Validation)
    AWEME_ID_PATTERN = r"^\d{19}$"


# ==================== 错误代码常量 (Error Code Constants) ====================
class ErrorCodes:
    """错误代码常量类"""
    
    # HTTP状态码 (HTTP Status Codes)
    HTTP_OK = 200
    HTTP_FOUND = 302
    HTTP_UNAUTHORIZED = 401
    HTTP_NOT_FOUND = 404
    HTTP_TIMEOUT = 408
    HTTP_TOO_MANY_REQUESTS = 429
    HTTP_SERVICE_UNAVAILABLE = 503
    
    # 自定义错误代码 (Custom Error Codes)
    API_CONNECTION_ERROR = "API_CONNECTION_ERROR"
    API_RESPONSE_ERROR = "API_RESPONSE_ERROR"
    API_TIMEOUT_ERROR = "API_TIMEOUT_ERROR"
    API_UNAVAILABLE_ERROR = "API_UNAVAILABLE_ERROR"
    API_UNAUTHORIZED_ERROR = "API_UNAUTHORIZED_ERROR"
    API_NOT_FOUND_ERROR = "API_NOT_FOUND_ERROR"
    API_RATE_LIMIT_ERROR = "API_RATE_LIMIT_ERROR"
    API_RETRY_EXHAUSTED_ERROR = "API_RETRY_EXHAUSTED_ERROR"
    
    # 业务错误代码 (Business Error Codes)
    INVALID_AWEME_ID = "INVALID_AWEME_ID"
    INVALID_SEC_USER_ID = "INVALID_SEC_USER_ID"
    INVALID_PARAMS = "INVALID_PARAMS"
    SIGNATURE_GENERATION_FAILED = "SIGNATURE_GENERATION_FAILED"
    JSON_DECODE_ERROR = "JSON_DECODE_ERROR"


# ==================== 正则表达式常量 (Regular Expression Constants) ====================
class RegexPatterns:
    """正则表达式常量类"""
    
    # URL编码过滤器 (URL Encoding Filter)
    URL_FILTER = r'%([0-9A-F]{2})'
    
    # JSON数据匹配 (JSON Data Matching)
    JSON_MATCH = r"\{.*\}"
    
    # sec_user_id格式验证 (sec_user_id Format Validation)
    SEC_USER_ID_PATTERN = r'^MS4wLjAB[A-Za-z0-9+/=_-]+$'
    
    # aweme_id格式验证 (aweme_id Format Validation)
    AWEME_ID_PATTERN = r'^\d{19}$'


# ==================== 时区常量 (Timezone Constants) ====================
class TimezoneConstants:
    """时区常量类"""
    
    # UTC+8时区偏移 (UTC+8 Timezone Offset)
    UTC8_OFFSET_HOURS = 8
    
    # 时间格式 (Time Formats)
    DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    DATE_FORMAT = "%Y-%m-%d"
    TIME_FORMAT = "%H:%M:%S"


# ==================== 文件路径常量 (File Path Constants) ====================
class FilePaths:
    """文件路径常量类（兼容旧引用，复用 OutputConfig 配置）"""
    
    # 日志目录 (Log Directory)
    DEFAULT_LOG_DIR = "logs"
    
    # 输出文件 (Output Files)
    COMMENT_ORIGINAL_FILE = OutputConfig.COMMENT_ORIGINAL_FILE
    COMMENT_SIMPLIFIED_FILE = OutputConfig.COMMENT_SIMPLIFIED_FILE
    USER_ORIGINAL_FILE = OutputConfig.USER_ORIGINAL_FILE
    USER_SIMPLIFIED_FILE = OutputConfig.USER_SIMPLIFIED_FILE
    VIDEO_ORIGINAL_FILE = OutputConfig.VIDEO_ORIGINAL_FILE
    VIDEO_SIMPLIFIED_FILE = OutputConfig.VIDEO_SIMPLIFIED_FILE


# ==================== 默认配置常量 (Default Configuration Constants) ====================
class DefaultConfig:
    """默认配置常量类 - 用于向后兼容"""
    
    # 默认请求头 (Default Headers)
    DEFAULT_HEADERS = {
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Referer": "https://www.douyin.com/",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    
    # 默认网络配置 (Default Network Configuration)
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_MAX_CONNECTIONS = 50
    DEFAULT_MAX_TASKS = 50
    
    # 默认分页配置 (Default Pagination Configuration)
    DEFAULT_CURSOR = 0
    DEFAULT_COUNT = 20
    
    # 默认设备信息 (Default Device Information)
    DEFAULT_DEVICE_INFO = {
        "device_platform": "webapp",
        "aid": "6383",
        "channel": "channel_pc_web",
        "pc_client_type": 1,
        "version_code": "290100",
        "version_name": "29.1.0",
        "cookie_enabled": "true",
        "screen_width": 1920,
        "screen_height": 1080,
        "browser_language": "zh-CN",
        "browser_platform": "Win32",
        "browser_name": "Chrome",
        "browser_version": "130.0.0.0",
        "browser_online": "true",
        "engine_name": "Blink",
        "engine_version": "130.0.0.0",
        "os_name": "Windows",
        "os_version": "10",
        "cpu_core_num": 12,
        "device_memory": 8,
        "platform": "PC",
        "downlink": "10",
        "effective_type": "4g",
        "from_user_page": "1",
        "locate_query": "false",
        "need_time_list": "1",
        "pc_libra_divert": "Windows",
        "publish_video_strategy_type": "2",
        "round_trip_time": "0",
        "show_live_replay_strategy": "1",
        "time_list_query": "0",
        "whale_cut_token": "",
        "update_version_code": "170400",
    }


# ==================== Token生成相关常量 (Token Generation Constants) ====================
class TokenConstants:
    """Token生成相关常量类 - 用于向后兼容"""
    
    # msToken生成 (msToken Generation)
    MS_TOKEN_MAGIC = 538969122
    MS_TOKEN_VERSION = 1
    MS_TOKEN_DATA_TYPE = 8
    MS_TOKEN_BASE_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    MS_TOKEN_LENGTH = 126
    
    # verifyFp生成 (verifyFp Generation)
    VERIFY_FP_BASE_STR = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    VERIFY_FP_PREFIX = "verify_"
    
    # ttwid生成数据 (ttwid Generation Data)
    TTWID_DATA = '{"region":"cn","aid":1768,"needFid":false,"service":"www.ixigua.com","migrate_info":{"ticket":"","source":"node"},"cbUrlProtocol":"https","union":true}'


# ==================== 签名算法常量 (Signature Algorithm Constants) ====================
class SignatureConstants:
    """签名算法常量类 - 用于向后兼容"""
    
    # XBogus相关常量 (XBogus Constants)
    XBOGUS_CHARACTER = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe="
    XBOGUS_UA_KEY = b"\x00\x01\x0c"
    
    # ABogus相关常量 (ABogus Constants)
    ABOGUS_ARGUMENTS = [0, 1, 14]
    ABOGUS_UA_KEY = "\u0000\u0001\u000e"
    ABOGUS_END_STRING = "cus"
    ABOGUS_VERSION = [1, 0, 1, 5]
    ABOGUS_BROWSER = "1536|742|1536|864|0|0|0|0|1536|864|1536|864|1536|742|24|24|MacIntel"
    ABOGUS_REG = [
        1937774191,
        1226093241,
        388252375,
        3666478592,
        2842636476,
        372324522,
        3817729613,
        2969243214,
    ]
    ABOGUS_STR = {
        "s0": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        "s1": "Dkdpgh4ZKsQB80/Mfvw36XI1R25+WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
        "s2": "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
        "s3": "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzKFjJnry79HbGDaStCe",
        "s4": "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe",
    }


# ==================== 日志配置常量 (Logging Configuration Constants) ====================
class LoggingConstants:
    """日志配置常量类 - 用于向后兼容"""
    
    # 日志级别 (Log Levels)
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    
    # 日志格式 (Log Formats)
    DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DETAILED_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s"
    
