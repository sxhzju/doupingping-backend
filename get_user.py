#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import argparse
import sys
import json
from pathlib import Path
import datetime

# 导入重构后的模块 (Import refactored modules)
try:
    from utils import (
        DouyinWebCrawler,
        save_json_file,
        validate_sec_user_id,
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


class UserProfileFetcher:
    """用户资料获取器类 (User Profile Fetcher Class)"""
    
    def __init__(self):
        """初始化用户资料获取器 (Initialize user profile fetcher)"""
        # 设置环境 (Setup environment)
        self.config_manager, self.logger = setup_environment()
        
        # 创建爬虫实例 (Create crawler instance)
        self.crawler = DouyinWebCrawler()
        
    
    async def fetch_user_profile(self, sec_user_id: str) -> dict:
        """
        获取用户资料 (Fetch user profile)
        
        Args:
            sec_user_id (str): 用户安全ID (User secure ID)
            
        Returns:
            dict: 用户资料数据 (User profile data)
        """
        # 验证参数 (Validate parameters)
        if not validate_sec_user_id(sec_user_id):
            error_msg = f"无效的sec_user_id格式: {sec_user_id}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        try:
            
            # 调用爬虫获取数据 (Call crawler to fetch data)
            result = await self.crawler.fetch_user_profile(sec_user_id)
            
            if not result:
                error_msg = "获取用户资料失败：返回空结果"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            
            # 检查是否有错误信息 (Check for error information)
            if 'error' in result:
                error_msg = f"API返回错误: {result['error']}"
                self.logger.error(error_msg)
                raise APIError(error_msg, ErrorCodes.API_RESPONSE_ERROR)
            
            # 检查API响应状态 (Check API response status)
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
        """
        根据用户需求简化用户资料数据 (Simplify user profile data based on user requirements)

        Args:
            result (dict): 原始用户资料数据 (Raw user profile data)

        Returns:
            dict: 包含特定字段的简化用户资料 (Simplified user profile with specific fields)
        """
        try:
            user_info = result.get('user', {})
            if not user_info:
                self.logger.warning("用户信息为空，无法简化")
                return {}

            # 将性别数字转换为文字
            gender_val = user_info.get('gender')
            gender_str = "未知"
            if gender_val == 1:
                gender_str = "男"
            elif gender_val == 2:
                gender_str = "女"

            # 处理响应时间
            response_timestamp_ms = result.get("extra", {}).get("now")
            response_time_str = None
            if response_timestamp_ms:
                ts_sec = response_timestamp_ms / 1000
                utc8_tz = datetime.timezone(datetime.timedelta(hours=8))
                dt_object = datetime.datetime.fromtimestamp(ts_sec, tz=utc8_tz)
                response_time_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')

            simplified_profile = {
                # 摘要信息
                "nickname": user_info.get("nickname"),
                "unique_id": user_info.get("unique_id"),
                "gender": gender_str,
                "age": user_info.get("user_age"),
                "signature": user_info.get("signature"),
                "aweme_count": user_info.get("aweme_count", 0),
                "following_count": user_info.get("following_count", 0),
                "follower_count": user_info.get("follower_count", 0),
                "total_favorited": user_info.get("total_favorited", 0),
                # 额外要求的信息
                "school_name": user_info.get("school_name"),
                "avatar_medium": user_info.get("avatar_medium", {}).get("url_list", []),
                "sec_uid": user_info.get("sec_uid"),
                # 响应时间
                "response_time": response_timestamp_ms,
                "response_time_utc8": response_time_str
            }
            
            return simplified_profile

        except Exception as e:
            self.logger.error(f"简化用户资料数据时发生错误: {e}")
            return {} # 返回空字典表示失败
    
    def save_results(self, original_result: dict, simplified_result: dict, 
                   save_original: bool = True, save_simplified: bool = True,
                   output_dir: str = None, filename: str = None) -> tuple:
        """
        保存结果到文件 (Save results to files)
        
        Args:
            original_result (dict): 原始用户资料数据 (Raw user profile data)
            simplified_result (dict): 简化的用户资料数据 (Simplified user profile data)
            save_original (bool): 是否保存原始结果 (Whether to save original result)
            save_simplified (bool): 是否保存简化结果 (Whether to save simplified result)
            output_dir (str): 输出目录 (Output directory)
            filename (str): 文件名 (已废弃) (Filename - deprecated)
            
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

            # 保存简化结果 (Save simplified result)
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

            return str(original_file) if original_file else None, str(simplified_file) if simplified_file else None
            
        except Exception as e:
            error_msg = f"保存文件时发生错误: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise


async def main():
    """主函数 (Main function)"""
    # Hardcoded parameters based on former argparse defaults
    SEC_USER_ID = "MS4wLjABAAAAW9FWcqS7RdQAWPd2AA5fL_ilmqsIFUCQ_Iym6Yh9_cUa6ZRqVLjVQSUjlHrfXY1Y"
    OUTPUT_DIR = None
    NO_SIMPLIFY = False
    NO_SAVE_ORIGINAL = False
    NO_SAVE_SIMPLIFIED = False
    PRINT_RESULT = False
    VERBOSE = False

    # 验证sec_user_id (Validate sec_user_id)
    if not validate_sec_user_id(SEC_USER_ID):
        print(f"警告: 提供的sec_user_id '{SEC_USER_ID}' 可能不是有效格式")
        print(f"Warning: The provided sec_user_id '{SEC_USER_ID}' might not be valid format")
        
        response = input("是否继续？(y/N): ")
        if response.lower() not in ['y', 'yes', '是']:
            print("操作已取消")
            return 1
    
    # 创建用户资料获取器 (Create user profile fetcher)
    fetcher = UserProfileFetcher()
    
    try:
        # 记录开始时间 (Record start time)
        print(f"正在获取用户资料: {SEC_USER_ID}")
        
        # 获取用户资料数据 (Fetch user profile data)
        result = await fetcher.fetch_user_profile(SEC_USER_ID)
        
        # 简化结果 (Simplify result)
        simplified_result = None
        if not NO_SIMPLIFY:
            simplified_result = fetcher.simplify_user_profile(result)
        
        # 打印结果到控制台 (Print result to console)
        if PRINT_RESULT:
            print("\n" + "="*50)
            if simplified_result and not NO_SIMPLIFY:
                print("用户资料 (User Profile):")
                print("="*50)
                print(json.dumps(simplified_result, ensure_ascii=False, indent=2))
            else:
                print("原始用户资料数据 (Raw User Profile Data):")
                print("="*50)
                print(json.dumps(result, ensure_ascii=False, indent=2))
        
        # 保存结果 (Save results)
        if not NO_SAVE_ORIGINAL or not NO_SAVE_SIMPLIFIED:
            original_file, simplified_file = fetcher.save_results(
                original_result=result,
                simplified_result=simplified_result,
                save_original=not NO_SAVE_ORIGINAL,
                save_simplified=not NO_SAVE_SIMPLIFIED and not NO_SIMPLIFY,
                output_dir=OUTPUT_DIR
            )
            
            print(f"\n任务完成! (Task completed!)")
            if original_file:
                print(f"原始用户资料文件: {original_file}")
            if simplified_file:
                print(f"简化用户资料文件: {simplified_file}")
        
        # 输出用户基本信息 (Output basic user information)
        if simplified_result and not NO_SIMPLIFY:
            print(f"\n用户信息摘要 (User Information Summary):")
            print(f"  昵称: {simplified_result.get('nickname', 'N/A')}")
            print(f"  抖音号: {simplified_result.get('unique_id', 'N/A')}")
            print(f"  性别: {simplified_result.get('gender', 'N/A')}")
            print(f"  年龄: {simplified_result.get('age', 'N/A')}")
            print(f"  个性签名: {simplified_result.get('signature', 'N/A')}")
            print(f"  作品数: {simplified_result.get('aweme_count', 0)}")
            print(f"  关注数: {simplified_result.get('following_count', 0)}")
            print(f"  粉丝数: {simplified_result.get('follower_count', 0)}")
            print(f"  获赞数: {simplified_result.get('total_favorited', 0)}")
        elif result.get('user'):
            user = result['user']
            print(f"\n用户信息摘要 (User Information Summary):")
            print(f"  昵称: {user.get('nickname', 'N/A')}")
            print(f"  唯一ID: {user.get('unique_id', 'N/A')}")
            print(f"  个性签名: {user.get('signature', 'N/A')}")
            print(f"  作品数: {user.get('aweme_count', 0)}")
            print(f"  关注数: {user.get('following_count', 0)}")
            print(f"  粉丝数: {user.get('follower_count', 0)}")
            print(f"  获赞数: {user.get('total_favorited', 0)}")
        
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