#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
from pathlib import Path

try:
    from utils import (
        DouyinWebCrawler,
        simplify_comment_result,
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


class CommentsFetcher:
    """Fetches Douyin comments and stores the results."""

    def __init__(self):
        self.config_manager, self.logger = setup_environment()
        self.crawler = DouyinWebCrawler()

    async def fetch_comments(self, aweme_id: str, cursor: int = 0, count: int = 20) -> dict:
        """Fetch video comments."""
        if not validate_aweme_id(aweme_id):
            error_msg = f"无效的aweme_id格式: {aweme_id}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        if cursor < 0:
            error_msg = f"cursor必须大于等于0: {cursor}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        if count <= 0 or count > 100:
            error_msg = f"count必须在1-100之间: {count}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        try:
            result = await self.crawler.fetch_video_comments(aweme_id, cursor, count)
            if not result:
                error_msg = "获取评论数据失败：返回空结果"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            if result.get('status_code') != 0:
                error_msg = f"API返回错误状态: {result.get('status_msg', '未知错误')}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            return result
        except APIError:
            raise
        except Exception as e:
            error_msg = f"获取评论时发生未知错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)

    def save_results(self, original_result: dict, simplified_result: dict,
                    save_original: bool = True, save_simplified: bool = True) -> tuple:
        """Persist original and simplified payloads."""
        output_config = self.config_manager.get_config_value('output', {})
        output_path = Path(__file__).parent / 'json'
        output_path.mkdir(parents=True, exist_ok=True)
        original_file = None
        simplified_file = None
        try:
            if save_original and output_config.get('save_original', True):
                original_filename = output_config.get('comment_original_file')
                original_file = output_path / original_filename
                save_json_file(
                    original_result,
                    str(original_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"原始评论数据已保存: {original_file}")
            if save_simplified and output_config.get('save_simplified', True):
                simplified_filename = output_config.get('comment_simplified_file')
                simplified_file = output_path / simplified_filename
                save_json_file(
                    simplified_result,
                    str(simplified_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"简化评论数据已保存: {simplified_file}")
            return str(original_file) if original_file else None, str(simplified_file) if simplified_file else None
        except Exception as e:
            error_msg = f"保存文件时发生错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise


async def main():
    """Run default comment download."""
    AWEME_ID = '7557971418924502324'
    CURSOR = 0
    COUNT = 20

    fetcher = CommentsFetcher()

    try:
        print(f"正在获取视频评论: https://www.douyin.com/video/{AWEME_ID}  CURSOR: {CURSOR} COUNT: {COUNT}")

        result = await fetcher.fetch_comments(AWEME_ID, CURSOR, COUNT)
        simplified_result = simplify_comment_result(result)
        original_file, simplified_file = fetcher.save_results(result, simplified_result)

        if original_file:
            print(f"原始数据文件: {original_file}")
        if simplified_file:
            print(f"简化数据文件: {simplified_file}")

        total_comments = len(result.get('comments', []))
        has_more = result.get('has_more', False)
        next_cursor = result.get('cursor', 0)
        print("")
        print("统计信息 (Statistics):")
        print(f"  获取评论数量: {total_comments}")
        print(f"  是否有更多: {'是' if has_more else '否'}")
        print(f"  下一页游标: {next_cursor}")
        if has_more:
            print("")
            print("获取下一页 (To get the next page):")
            print(f"  请在 get_comments.py 脚本的 main 函数中，将 CURSOR 的值修改为 {next_cursor}，然后重新运行。")

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
