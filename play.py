#!/usr/bin/env python3
"""
海康威视 WebSocket 视频播放与抓图程序
基于 hik_ws_client.py 配合 FFMPEG 和 OpenCV 实现实时播放与每秒截帧保存。

请确保已安装 OpenCV: pip install opencv-python
"""

import asyncio
import argparse
import logging
import sys
import time
import subprocess
import threading
from pathlib import Path
import cv2
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from hik_ws_client import (
    HikMediaClient, HikConfig, parse_proxy_url
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# 全局变量缓存最新帧和运行状态
latest_frame = None
is_running = True

def ffmpeg_decoder_thread(stdin_queue, ffmpeg_proc):
    """
    负责从 stdout 读取 FFMPEG 解码出的 MJPEG 流并提取为独立的 JPEG 帧
    """
    global latest_frame, is_running
    bytes_data = b''
    
    while is_running:
        try:
            chunk = ffmpeg_proc.stdout.read(4096)
            if not chunk:
                break
            bytes_data += chunk
            
            # 查找 JPEG 图片的 SOI (FF D8) 和 EOI (FF D9)
            while True:
                start_idx = bytes_data.find(b'\xff\xd8')
                end_idx = bytes_data.find(b'\xff\xd9')
                
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    # 提取出一张完整的 JPG
                    jpg_data = bytes_data[start_idx:end_idx+2]
                    bytes_data = bytes_data[end_idx+2:]
                    
                    # 使用 CV2 解码 JPEG
                    frame = cv2.imdecode(np.frombuffer(jpg_data, dtype=np.uint8), cv2.IMREAD_COLOR)
                    if frame is not None:
                        latest_frame = frame
                else:
                    break
        except Exception as e:
            logger.error(f"Error reading ffmpeg output: {e}")
            break

def ffmpeg_writer_thread(video_queue, ffmpeg_proc):
    """
    负责将 Web socket 收到的二进制数据流写入 FFMPEG 的 stdin
    """
    global is_running
    while is_running:
        try:
            # 阻塞等待数据
            item = video_queue.get(timeout=1.0)
            if item is None: # 结束信号
                break
            ffmpeg_proc.stdin.write(item)
            ffmpeg_proc.stdin.flush()
        except Exception:
            pass

async def main():
    global latest_frame, is_running
    parser = argparse.ArgumentParser(description='Hikvision WebSocket Player & Saver')
    parser.add_argument('url', help='Full Hikvision proxy URL')
    parser.add_argument('-u', '--username', default='admin', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('--output-dir', default='./output', help='Screenshot output directory')
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    config = parse_proxy_url(args.url)
    if args.username != 'admin':
        config.username = args.username
    if args.password:
        config.password = args.password
        
    logger.info(f"Connecting to device via {config.proxy_host}...")
    
    # 启动 FFmpeg 子进程解码
    ffmpeg_cmd = [
        'ffmpeg',
        '-hide_banner', '-sn', '-an',
        '-i', 'pipe:0',             # 从标准输入读取视频流
        '-f', 'image2pipe',         # 输出为图片管道流
        '-vcodec', 'mjpeg',         # 使用 mjpeg 编码格式
        '-v', 'error',
        'pipe:1'                    # 输出到标准输出
    ]
    
    try:
        ffmpeg_proc = subprocess.Popen(
            ffmpeg_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        logger.error("未找到 FFMPEG！请先安装 ffmpeg (如：brew install ffmpeg 或 sudo apt install ffmpeg)。")
        return
        
    import queue
    video_queue = queue.Queue(maxsize=100)
    
    # 收发线程
    reader_th = threading.Thread(target=ffmpeg_decoder_thread, args=(video_queue, ffmpeg_proc))
    writer_th = threading.Thread(target=ffmpeg_writer_thread, args=(video_queue, ffmpeg_proc))
    reader_th.daemon = True
    writer_th.daemon = True
    reader_th.start()
    writer_th.start()

    client = HikMediaClient(config)
    def on_video(data):
        try:
            # 放入队列供 ffmpeg_writer 消费
            video_queue.put_nowait(data)
        except queue.Full:
            pass
            
    client.on_video_data = on_video

    # 将运行放在后台 task 中，保证主线程用来展示 CV2 的 imshow
    task = asyncio.create_task(client.run())
    
    last_save_time = time.time()
    logger.info("开始播放视频。按 'q' 键退出。")
    cv2.namedWindow("Hikvision Video Stream", cv2.WINDOW_NORMAL)

    try:
        while not task.done():
            # 获取最新视频帧展示
            if latest_frame is not None:
                cv2.imshow("Hikvision Video Stream", latest_frame)
                
                # 每秒保存一张图
                current_time = time.time()
                if current_time - last_save_time >= 1.0:
                    last_save_time = current_time
                    filename = output_dir / f"frame_{int(current_time)}.jpg"
                    cv2.imwrite(str(filename), latest_frame)
                    logger.info(f"已保存抓图: {filename}")
            
            # 检测按键，主线程短暂休眠以刷新窗口
            key = cv2.waitKey(30) & 0xFF
            if key == ord('q'):
                break
                
            await asyncio.sleep(0.01)
            
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("正在退出...")
        is_running = False
        video_queue.put(None)
        await client.close()
        task.cancel()
        
        if ffmpeg_proc:
            try:
                ffmpeg_proc.stdin.close()
                ffmpeg_proc.terminate()
                ffmpeg_proc.wait(timeout=2)
            except:
                pass
                
        cv2.destroyAllWindows()

if __name__ == '__main__':
    asyncio.run(main())
