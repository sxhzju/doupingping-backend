#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
from pathlib import Path
from typing import Optional, Tuple

try:
    from utils import (
        DouyinWebCrawler,
        simplify_video_result,
        save_json_file,
        validate_aweme_id,
        setup_environment,
        APIError,
    )
    from constants import ErrorCodes
except ImportError as e:
    print(f"Error: 无法导入必需的模块: {e}")
    print("请确保 utils.py 和 constants.py 文件在同一目录下")
    print("Please ensure utils.py and constants.py files are in the same directory")
    sys.exit(1)


class VideoDetailFetcher:
    """Fetches Douyin video details and stores the results."""

    def __init__(self):
        self.config_manager, self.logger = setup_environment()
        self.crawler = DouyinWebCrawler()

    async def fetch_video_detail(self, aweme_id: str) -> dict:
        """Fetch video detail payload."""
        if not validate_aweme_id(aweme_id):
            error_msg = f"无效的aweme_id格式: {aweme_id}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        try:
            result = await self.crawler.fetch_video_data(aweme_id)
            if not result:
                error_msg = "获取视频数据失败：返回空结果"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            status_code = result.get('status_code')
            if status_code is not None and status_code != 0:
                error_msg = f"API返回错误状态: {result.get('status_msg', '未知错误')}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            return result
        except APIError:
            raise
        except Exception as e:
            error_msg = f"获取视频数据时发生未知错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)

    def save_results(
        self,
        original_result: dict,
        simplified_result: Optional[dict],
        save_original: bool = True,
        save_simplified: bool = True,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Persist original and simplified payloads."""
        output_config = self.config_manager.get_config_value('output', {})
        output_path = Path(__file__).parent / 'json'
        output_path.mkdir(parents=True, exist_ok=True)

        original_file = simplified_file = None
        try:
            if save_original and output_config.get('save_original', True) and original_result:
                original_filename = output_config.get('video_original_file')
                original_file = output_path / original_filename
                save_json_file(
                    original_result,
                    str(original_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=output_config.get('ensure_ascii', False),
                )
                self.logger.info(f"原始视频数据已保存: {original_file}")

            if (
                save_simplified
                and output_config.get('save_simplified', True)
                and simplified_result is not None
            ):
                simplified_filename = output_config.get('video_simplified_file')
                simplified_file = output_path / simplified_filename
                save_json_file(
                    simplified_result,
                    str(simplified_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=output_config.get('ensure_ascii', False),
                )
                self.logger.info(f"简化视频数据已保存: {simplified_file}")

            return (
                str(original_file) if original_file else None,
                str(simplified_file) if simplified_file else None,
            )
        except Exception as e:
            error_msg = f"保存文件时发生错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise


async def main():
    """Run default video detail download."""
    AWEME_ID = "7372484719365098803"

    fetcher = VideoDetailFetcher()

    try:
        print(f"正在获取视频信息: https://www.douyin.com/video/{AWEME_ID}")

        result = await fetcher.fetch_video_detail(AWEME_ID)
        simplified_result = simplify_video_result(result)
        summary_data = simplified_result

        original_file = simplified_file = None
        original_file, simplified_file = fetcher.save_results(
            original_result=result,
            simplified_result=simplified_result,
        )

        if original_file:
            print(f"原始视频数据文件: {original_file}")
        if simplified_file:
            print(f"简化视频数据文件: {simplified_file}")

        if summary_data:
            author_info = summary_data.get('author', {}) or {}
            statistics = summary_data.get('statistics', {}) or {}
            print("")
            print("视频信息摘要 (Video Information Summary):")
            print(f"  标题: {summary_data.get('title', 'N/A')}")
            print(f"  作者昵称: {author_info.get('nickname', 'N/A')}")
            print(f"  抖音号: {author_info.get('unique_id', 'N/A')}")
            print(f"  发布时间: {summary_data.get('publish_time_utc8', 'N/A')}")
            print(f"  播放次数: {statistics.get('play_count', 'N/A')}")
            print(f"  点赞次数: {statistics.get('digg_count', 'N/A')}")
            print(f"  评论次数: {statistics.get('comment_count', 'N/A')}")
            print(f"  分享次数: {statistics.get('share_count', 'N/A')}")

        return 0

    except KeyboardInterrupt:
        fetcher.logger.warning("用户中断操作")
        return 1
    except ValueError as e:
        fetcher.logger.error(f"参数错误: {e}")
        return 1
    except APIError as e:
        fetcher.logger.error(f"API错误: {e.message}")
        return 1
    except Exception as e:
        fetcher.logger.error(f"未知错误: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
