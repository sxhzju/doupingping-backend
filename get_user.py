#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
from pathlib import Path
import datetime

try:
    from utils import (
        DouyinWebCrawler,
        save_json_file,
        validate_sec_user_id,
        setup_environment,
        APIError,
    )
    from constants import ErrorCodes
except ImportError as e:
    print(f"Error: 无法导入必需的模块: {e}")
    print("请确保 utils.py 和 constants.py 文件在同一目录下")
    print("Please ensure utils.py and constants.py files are in the same directory")
    sys.exit(1)


class UserProfileFetcher:
    """Fetches Douyin user profiles and stores the results."""

    def __init__(self):
        self.config_manager, self.logger = setup_environment()
        self.crawler = DouyinWebCrawler()

    async def fetch_user_profile(self, sec_user_id: str) -> dict:
        """Fetch user profile data."""
        if not validate_sec_user_id(sec_user_id):
            error_msg = f"无效的sec_user_id格式: {sec_user_id}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        try:
            result = await self.crawler.fetch_user_profile(sec_user_id)
            if not result:
                error_msg = "获取用户资料失败：返回空结果"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            if 'error' in result:
                error_msg = f"API返回错误: {result['error']}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            if result.get('status_code') and result.get('status_code') != 0:
                error_msg = f"API返回错误状态: {result.get('status_msg', '未知错误')}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            return result
        except APIError:
            raise
        except Exception as e:
            error_msg = f"获取用户资料时发生未知错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)

    def simplify_user_profile(self, result: dict) -> dict:
        """Return the streamlined subset of the profile."""
        try:
            user_info = result.get('user', {})
            if not user_info:
                self.logger.warning("用户信息为空，无法简化")
                return {}

            gender_val = user_info.get('gender')
            gender = "未知"
            if gender_val == 1:
                gender = "男"
            elif gender_val == 2:
                gender = "女"

            response_timestamp_ms = result.get("extra", {}).get("now")
            response_time_str = None
            if response_timestamp_ms:
                ts_sec = response_timestamp_ms / 1000
                utc8_tz = datetime.timezone(datetime.timedelta(hours=8))
                dt_object = datetime.datetime.fromtimestamp(ts_sec, tz=utc8_tz)
                response_time_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')

            return {
                "nickname": user_info.get("nickname"),
                "unique_id": user_info.get("unique_id"),
                "gender": gender,
                "age": user_info.get("user_age"),
                "signature": user_info.get("signature"),
                "aweme_count": user_info.get("aweme_count", 0),
                "following_count": user_info.get("following_count", 0),
                "follower_count": user_info.get("follower_count", 0),
                "total_favorited": user_info.get("total_favorited", 0),
                "school_name": user_info.get("school_name"),
                "avatar_medium": user_info.get("avatar_medium", {}).get("url_list", []),
                "sec_uid": user_info.get("sec_uid"),
                "response_time": response_timestamp_ms,
                "response_time_utc8": response_time_str,
            }
        except Exception as e:
            self.logger.error(f"简化用户资料数据时发生错误: {e}")
            return {}

    def save_results(
        self,
        original_result: dict,
        simplified_result: dict,
        save_original: bool = True,
        save_simplified: bool = True,
    ) -> tuple:
        """Persist original and simplified payloads."""
        output_config = self.config_manager.get_config_value('output', {})
        output_path = Path(__file__).parent / 'json'
        output_path.mkdir(parents=True, exist_ok=True)
        original_file = simplified_file = None
        try:
            if save_original and original_result:
                original_filename = output_config.get('user_original_file', 'user_original.json')
                original_file = output_path / original_filename
                save_json_file(
                    original_result,
                    str(original_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"原始用户资料数据已保存: {original_file}")

            if save_simplified and simplified_result:
                simplified_filename = output_config.get('user_simplified_file', 'user_simplified.json')
                simplified_file = output_path / simplified_filename
                save_json_file(
                    simplified_result,
                    str(simplified_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"简化用户资料数据已保存: {simplified_file}")

            return (
                str(original_file) if original_file else None,
                str(simplified_file) if simplified_file else None,
            )
        except Exception as e:
            error_msg = f"保存文件时发生错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise


async def main():
    """Run default user profile download."""
    SEC_USER_ID = "MS4wLjABAAAAW9FWcqS7RdQAWPd2AA5fL_ilmqsIFUCQ_Iym6Yh9_cUa6ZRqVLjVQSUjlHrfXY1Y"
    SAVE_ORIGINAL = True
    SAVE_SIMPLIFIED = True

    if not validate_sec_user_id(SEC_USER_ID):
        print(f"警告: 提供的sec_user_id '{SEC_USER_ID}' 可能不是有效格式")
        print(f"Warning: The provided sec_user_id '{SEC_USER_ID}' might not be valid format")
        response = input("是否继续？(y/N): ")
        if response.lower() not in ['y', 'yes', '是']:
            print("操作已取消")
            return 1

    fetcher = UserProfileFetcher()

    try:
        print(f"正在获取用户资料: {SEC_USER_ID}")
        result = await fetcher.fetch_user_profile(SEC_USER_ID)
        simplified_result = fetcher.simplify_user_profile(result)

        original_file = simplified_file = None
        if SAVE_ORIGINAL or (SAVE_SIMPLIFIED and simplified_result):
            original_file, simplified_file = fetcher.save_results(
                original_result=result,
                simplified_result=simplified_result,
                save_original=SAVE_ORIGINAL,
                save_simplified=SAVE_SIMPLIFIED and simplified_result is not None,
            )

        summary_lines = ["任务完成! (Task completed!)"]
        if original_file:
            summary_lines.append(f"原始用户资料文件: {original_file}")
        if simplified_file:
            summary_lines.append(f"简化用户资料文件: {simplified_file}")

        summary_source = simplified_result if simplified_result else result.get('user') or {}
        if summary_source:
            age_value = summary_source.get('age', 'N/A') if simplified_result else summary_source.get('user_age', 'N/A')
            summary_lines.append("")
            summary_lines.append("用户信息摘要 (User Information Summary):")
            summary_lines.append(f"  昵称: {summary_source.get('nickname', 'N/A')}")
            summary_lines.append(f"  抖音号: {summary_source.get('unique_id', 'N/A')}")
            summary_lines.append(f"  性别: {summary_source.get('gender', 'N/A')}")
            summary_lines.append(f"  年龄: {age_value}")
            summary_lines.append(f"  个性签名: {summary_source.get('signature', 'N/A')}")
            summary_lines.append(f"  作品数: {summary_source.get('aweme_count', 0)}")
            summary_lines.append(f"  关注数: {summary_source.get('following_count', 0)}")
            summary_lines.append(f"  粉丝数: {summary_source.get('follower_count', 0)}")
            summary_lines.append(f"  获赞数: {summary_source.get('total_favorited', 0)}")

        print("\n".join(summary_lines))

        return 0

    except KeyboardInterrupt:
        logger.warning("用户中断操作")
        return 1

    except ValueError as e:
        logger.error(f"参数错误: {e}")
        return 1

    except APIError as e:
        logger.error(f"API错误: {e.message}")
        return 1

    except Exception as e:
        logger.error(f"未知错误: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
