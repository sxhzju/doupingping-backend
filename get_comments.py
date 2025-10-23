#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import argparse
import sys
from pathlib import Path

try:
    from utils import (
        DouyinWebCrawler, 
        simplify_comment_result, 
        save_json_file,
        validate_aweme_id,
        setup_environment,
        get_current_timestamp,
        create_output_filename,
        LoggerManager,
        APIError
    )
    from constants import FilePaths, ErrorCodes
except ImportError as e:
    print(f"Error: 无法导入必需的模块: {e}")
    print("请确保 utils.py 和 constants.py 文件在同一目录下")
    print("Please ensure utils.py and constants.py files are in the same directory")
    sys.exit(1)


class CommentsFetcher:
    """评论获取器类 (Comments Fetcher Class)"""
    
    def __init__(self):
        """初始化评论获取器 (Initialize comments fetcher)"""
        # 设置环境 (Setup environment)
        self.config_manager, self.logger = setup_environment()
        
        # 创建爬虫实例 (Create crawler instance)
        self.crawler = DouyinWebCrawler()
        
    
    async def fetch_comments(self, aweme_id: str, cursor: int = 0, count: int = 20) -> dict:
        """
        获取视频评论 (Fetch video comments)
        
        Args:
            aweme_id (str): 视频ID (Video ID)
            cursor (int): 分页游标 (Pagination cursor)
            count (int): 每页数量 (Items per page)
            
        Returns:
            dict: 评论数据 (Comment data)
        """
        # 验证参数 (Validate parameters)
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
            
            # 调用爬虫获取数据 (Call crawler to fetch data)
            result = await self.crawler.fetch_video_comments(aweme_id, cursor, count)
            
            if not result:
                error_msg = "获取评论数据失败：返回空结果"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            
            # 检查API响应状态 (Check API response status)
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
                    save_original: bool = True, save_simplified: bool = True,
                    output_dir: str = None) -> tuple:
        """
        保存结果到文件 (Save results to files)
        
        Args:
            original_result (dict): 原始结果 (Original result)
            simplified_result (dict): 简化结果 (Simplified result)
            save_original (bool): 是否保存原始结果 (Whether to save original result)
            save_simplified (bool): 是否保存简化结果 (Whether to save simplified result)
            output_dir (str): 输出目录 (Output directory)
            
        Returns:
            tuple: (原始文件路径, 简化文件路径) (Original file path, simplified file path)
        """
        output_config = self.config_manager.get_config_value('output', {})
        
        # 设置输出目录 (Set output directory)
        if output_dir:
            output_path = Path(output_dir)
        else:
            output_path = Path(__file__).parent / 'json'
        output_path.mkdir(parents=True, exist_ok=True)
        
        original_file = None
        simplified_file = None
        
        try:
            # 保存原始结果 (Save original result)
            if save_original and output_config.get('save_original', True):
                original_filename = output_config.get('comment_original_file', FilePaths.COMMENT_ORIGINAL_FILE)
                original_file = output_path / original_filename
                save_json_file(
                    original_result,
                    str(original_file),
                    indent=output_config.get('indent', 2),
                    ensure_ascii=False
                )
                self.logger.info(f"原始评论数据已保存: {original_file}")
            
            # 保存简化结果 (Save simplified result)
            if save_simplified and output_config.get('save_simplified', True):
                simplified_filename = output_config.get('comment_simplified_file', FilePaths.COMMENT_SIMPLIFIED_FILE)
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
    """主函数 (Main function)"""
    # Hardcoded parameters based on former argparse defaults
    AWEME_ID = '7557971418924502324'
    CURSOR = 0
    COUNT = 20
    OUTPUT_DIR = None
    NO_SAVE_ORIGINAL = False
    NO_SAVE_SIMPLIFIED = False
    PRINT_RESULT = False
    VERBOSE = False

    # 创建评论获取器 (Create comments fetcher)
    fetcher = CommentsFetcher()
    
    try:
        # 记录开始时间 (Record start time)
        print(f"正在获取视频评论: {AWEME_ID}")
        
        # 获取评论数据 (Fetch comment data)
        result = await fetcher.fetch_comments(AWEME_ID, CURSOR, COUNT)
        
        # 简化结果 (Simplify result)
        simplified_result = simplify_comment_result(result)
        
        # 打印结果到控制台 (Print result to console)
        if PRINT_RESULT:
            print("\n" + "="*50)
            print("原始结果 (Original Result):")
            print("="*50)
            import json
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            print("\n" + "="*50)
            print("简化结果 (Simplified Result):")
            print("="*50)
            print(json.dumps(simplified_result, ensure_ascii=False, indent=2))
        
        # 保存结果 (Save results)
        if not NO_SAVE_ORIGINAL or not NO_SAVE_SIMPLIFIED:
            original_file, simplified_file = fetcher.save_results(
                result, 
                simplified_result,
                save_original=not NO_SAVE_ORIGINAL,
                save_simplified=not NO_SAVE_SIMPLIFIED,
                output_dir=OUTPUT_DIR
            )
            
            print(f"\n任务完成! (Task completed!)")
            if original_file:
                print(f"原始数据文件: {original_file}")
            if simplified_file:
                print(f"简化数据文件: {simplified_file}")
        
        # 输出统计信息 (Output statistics)
        total_comments = len(result.get('comments', []))
        has_more = result.get('has_more', False)
        next_cursor = result.get('cursor', 0)
        
        print(f"\n统计信息 (Statistics):")
        print(f"  获取评论数量: {total_comments}")
        print(f"  是否有更多: {'是' if has_more else '否'}")
        print(f"  下一页游标: {next_cursor}")
        
        if has_more:
            print(f"\n获取下一页 (To get the next page):")
            print(f"  请在 get_comments.py 脚本的 main 函数中，将 CURSOR 的值修改为 {next_cursor}，然后重新运行。")

        # 记录结束时间 (Record end time)
        
        return 0
        
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
        if VERBOSE:
            print(f"错误代码: {e.code}")
            if e.context:
                print(f"错误上下文: {e.context}")
        return 1
        
    except Exception as e:
        fetcher.logger.error(f"未知错误: {e}", exc_info=True)
        print(f"发生未知错误: {e}")
        if VERBOSE:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    # 设置事件循环策略 (Set event loop policy)
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # 运行主函数 (Run main function)
    exit_code = asyncio.run(main())
    sys.exit(exit_code)