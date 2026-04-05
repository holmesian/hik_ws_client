#!/usr/bin/env python3
"""
海康威视 WebSocket 客户端演示程序

Usage:
    python3 demo.py "wss://ipcbasehkvideolj.example.com.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/mYqWpMI" --username admin --password ""
    
    # 或者直接使用媒体端点
    python3 demo.py --host ipcbasehkvideolj.example.com.com --port 6014 --device-ip "[fd00:0:2c0:9::10c]" --device-port 559
"""

import asyncio
import argparse
import logging
import sys
import time
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from hik_ws_client import (
    HikMediaClient, HikConfig, parse_proxy_url, HikCrypto, HikProtocol
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class VideoSaver:
    """简单的视频数据保存器"""
    
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.frame_count = 0
        self.start_time = time.time()
        self.last_log_time = self.start_time
        
    def save_frame(self, data: bytes):
        """保存视频帧数据"""
        self.frame_count += 1
        
        # 解析帧头
        if len(data) < 20:
            return
            
        # 海康视频帧头结构 (简化)
        # 0x24 0x34 0x00 0x00 [4字节长度] [其他信息]
        frame_type = data[0] if len(data) > 0 else 0
        
        # 简单的帧类型判断
        is_key_frame = (data[4] & 0x01) == 0x01 if len(data) > 4 else False
        
        # 每秒只打印一次状态
        current_time = time.time()
        if current_time - self.last_log_time >= 1.0:
            fps = self.frame_count / (current_time - self.start_time)
            logger.info(f"Frames: {self.frame_count}, FPS: {fps:.2f}, Last: {len(data)} bytes")
            self.last_log_time = current_time


async def main():
    parser = argparse.ArgumentParser(
        description='Hikvision WebSocket Demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using full URL
  python3 demo.py "wss://example.com:6014/proxy/192.168.1.64:8000/openUrl/abc123"
  
  # Using individual parameters
  python3 demo.py --host example.com --port 6014 --device-ip 192.168.1.64 --device-port 8000
        """
    )
    
    parser.add_argument('url', nargs='?', help='Full Hikvision proxy URL')
    parser.add_argument('--host', help='Proxy server hostname')
    parser.add_argument('--port', type=int, default=6014, help='Proxy server port')
    parser.add_argument('--device-ip', help='Device IP address (can be IPv6)')
    parser.add_argument('--device-port', type=int, default=8000, help='Device port')
    parser.add_argument('-u', '--username', default='admin', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--save-frames', action='store_true', help='Save video frames to disk')
    parser.add_argument('--output-dir', default='./output', help='Output directory for frames')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 构建配置
    if args.url:
        config = parse_proxy_url(args.url)
        # 只在命令行显式提供密码时才覆盖
        if args.password:
            config.password = args.password
        if args.username != 'admin':  # 只有非默认值才覆盖
            config.username = args.username
    elif args.host and args.device_ip:
        config = HikConfig(
            proxy_host=args.host,
            proxy_port=args.port,
            proxy_path=f"/proxy/{args.device_ip}:{args.device_port}",
            device_ip=args.device_ip,
            device_port=args.device_port,
            username=args.username,
            password=args.password
        )
    else:
        parser.error("Either URL or --host and --device-ip must be provided")
        return 1
    
    logger.info("=" * 50)
    logger.info("Hikvision WebSocket Demo")
    logger.info("=" * 50)
    logger.info(f"Proxy: {config.proxy_host}:{config.proxy_port}")
    logger.info(f"Device: {config.device_ip}:{config.device_port}")
    logger.info(f"Username: {config.username}")
    logger.info("=" * 50)
    
    # 创建视频保存器
    saver = VideoSaver(args.output_dir) if args.save_frames else None
    
    # 创建回调
    def on_video(data):
        if saver:
            saver.save_frame(data)
        # 也可以在这里处理视频帧
    
    def on_audio(data):
        logger.debug(f"Audio: {len(data)} bytes")
    
    def on_error(error):
        logger.error(f"Error: {error}")
    
    def on_connected():
        logger.info("Connected!")
    
    # 创建并运行客户端
    client = HikMediaClient(config)
    client.on_video_data = on_video
    client.on_audio_data = on_audio
    client.on_error = on_error
    client.on_connected = on_connected
    
    try:
        await client.run()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        await client.close()
    
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
