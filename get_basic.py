#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
from pathlib import Path

try:
    from utils import (
        DouyinWebCrawler,
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


class VideoFetcher:
    """Fetches Douyin video info and stores the results."""

    def __init__(self):
        self.config_manager, self.logger = setup_environment()
        self.crawler = DouyinWebCrawler()

    async def fetch_one_video(self, aweme_id: str):
        """
        Fetches data for a single video from Douyin using its aweme_id.
        """
        self.logger.info(f"Fetching video with aweme_id: {aweme_id}")

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
            if result.get('status_code') != 0:
                error_msg = f"API返回错误状态: {result.get('status_msg', '未知错误')}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            return result
        except APIError:
            raise
        except Exception as e:
            error_msg = f"获取视频时发生未知错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)

    def save_results(self, original_result: dict, save_original: bool = True) -> str:
        """Persist original payload."""
        output_config = self.config_manager.get_config_value('output', {})
        output_path = Path(__file__).parent / 'json'
        output_path.mkdir(parents=True, exist_ok=True)
        
        original_file = None
        try:
            if save_original and output_config.get('save_original', True):
                original_filename = output_config.get('video_original_file', 'basic_original.json')
                original_file = output_path / original_filename
                save_json_file(
                    original_result,
                    str(original_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"原始视频数据已保存: {original_file}")
            return str(original_file) if original_file else None
        except Exception as e:
            error_msg = f"保存文件时发生错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise


async def main():
    """ Main function to run the script. """
    # You can change this to any video ID you want to test
    AWEME_ID = "7372484719365098803"
    
    fetcher = VideoFetcher()
    
    try:
        # Log the video information with the URL
        print(f"获取 AWEME_ID 视频的信息！地址：https://www.douyin.com/jingxuan?modal_id={AWEME_ID}")
        
        video_data = await fetcher.fetch_one_video(AWEME_ID)

        if video_data:
            original_file = fetcher.save_results(video_data)
            
            print(f"\n任务完成! (Task completed!)")
            if original_file:
                print(f"原始视频数据文件: {original_file}")
                
            # Print summary information
            aweme_detail = video_data.get('aweme_detail', {})
            if aweme_detail:
                print(f"\n视频信息摘要 (Video Information Summary):")
                print(f"  标题: {aweme_detail.get('desc', 'N/A')}")
                print(f"  作者昵称: {aweme_detail.get('author', {}).get('nickname', 'N/A')}")
                print(f"  播放次数: {aweme_detail.get('statistics', {}).get('play_count', 'N/A')}")
                print(f"  点赞次数: {aweme_detail.get('statistics', {}).get('digg_count', 'N/A')}")
                print(f"  评论次数: {aweme_detail.get('statistics', {}).get('comment_count', 'N/A')}")
                print(f"  分享次数: {aweme_detail.get('statistics', {}).get('share_count', 'N/A')}")
            return 0
        else:
            print("\n" + "="*50)
            print("Failed to fetch video data.")
            print("="*50 + "\n")
            return 1
            
    except KeyboardInterrupt:
        fetcher.logger.info("用户中断操作")
        print("\n操作被用户中断 (Operation interrupted by user)")
        return 1
    except ValueError as e:
        fetcher.logger.error(f"参数错误: {e}")
        print(f"参数错误: {e}")
        return 1
    except APIError as e:
        fetcher.logger.error(f"API错误: {e.message}")
        print(f"API错误: {e.message}")
        return 1
    except Exception as e:
        fetcher.logger.error(f"未知错误: {e}", exc_info=True)
        print(f"发生未知错误: {e}")
        return 1


if __name__ == "__main__":
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
