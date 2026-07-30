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
    """视频原始码流保存器

    将收到的原始帧数据连续写入一个 dump 文件（stream_<时间戳>.raw），
    可供后续 ffmpeg/解码器离线分析。
    """

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.frame_count = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_log_time = self.start_time
        self.dump_path = self.output_dir / f"stream_{int(self.start_time)}.raw"
        self._fp = open(self.dump_path, 'wb')
        logger.info(f"Saving raw stream to {self.dump_path}")

    def save_frame(self, data: bytes):
        """保存视频帧数据"""
        self.frame_count += 1
        self.total_bytes += len(data)

        try:
            self._fp.write(data)
        except OSError as e:
            logger.error(f"Failed to write frame: {e}")
            return

        # 每秒只打印一次状态
        current_time = time.time()
        if current_time - self.last_log_time >= 1.0:
            elapsed = max(current_time - self.start_time, 1e-6)
            fps = self.frame_count / elapsed
            logger.info(
                f"Frames: {self.frame_count}, FPS: {fps:.2f}, "
                f"Total: {self.total_bytes / 1024:.1f} KB, Last: {len(data)} bytes")
            self.last_log_time = current_time

    def close(self):
        """关闭 dump 文件"""
        try:
            self._fp.flush()
            self._fp.close()
            logger.info(
                f"Stream dump closed: {self.dump_path} "
                f"({self.frame_count} frames, {self.total_bytes} bytes)")
        except OSError:
            pass


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
    parser.add_argument('-u', '--username', default=None, help='Username (overrides URL)')
    parser.add_argument('-p', '--password', default=None, help='Password (overrides URL)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--save-frames', action='store_true', help='Save video frames to disk')
    parser.add_argument('--output-dir', default='./output', help='Output directory for frames')
    parser.add_argument('--reconnect', action='store_true', help='Auto reconnect on failure')

    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 构建配置
    if args.url:
        config = parse_proxy_url(args.url)
        # 只在命令行显式提供时才覆盖 URL 中解析出的值
        if args.password is not None:
            config.password = args.password
        if args.username is not None:
            config.username = args.username
    elif args.host and args.device_ip:
        config = HikConfig(
            proxy_host=args.host,
            proxy_port=args.port,
            proxy_path=f"/proxy/{args.device_ip}:{args.device_port}",
            device_ip=args.device_ip,
            device_port=args.device_port,
            username=args.username or 'admin',
            password=args.password or ''
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
        if args.reconnect:
            await client.run_forever()
        else:
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
        if saver:
            saver.close()
    
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
