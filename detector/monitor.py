"""
monitor.py

This module is responsible for continuously tailing the Nginx access log file in real-time.
It handles log rotation (both file truncation and recreation) by monitoring the file's
inode and size. Each line is parsed as JSON and yielded as a dictionary.
It operates as a continuous generator, sleeping briefly when no new lines are available.
"""

import os
import time
import json
import logging
from typing import Dict, Any, Generator

logger = logging.getLogger(__name__)

def tail_log(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Continuously tails a log file, yielding parsed JSON log entries.
    Handles file rotation and truncation gracefully.
    
    Args:
        file_path (str): The absolute path to the log file to tail.
        
    Yields:
        Dict[str, Any]: Parsed log entry containing source_ip, timestamp, method, path, status, response_size.
    """
    while not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
        logger.warning(f"Waiting for log file to be readable: {file_path}")
        time.sleep(2.0)
    f = open(file_path, 'r', encoding='utf-8')
    f.seek(0, os.SEEK_END)
    current_inode = os.stat(file_path).st_ino
    
    while True:
        pos = f.tell()
        line = f.readline()
        
        if not line:
            try:
                stat = os.stat(file_path)
                new_inode = stat.st_ino
                new_size = stat.st_size
                
                # Check if the file was rotated (new inode) or truncated (size decreased)
                if new_inode != current_inode or new_size < pos:
                    logger.debug("Log rotation or truncation detected. Reopening file.")
                    f.close()
                    time.sleep(0.1)
                    while not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                        logger.warning(f"Waiting for log file to be readable: {file_path}")
                        time.sleep(2.0)
                    f = open(file_path, 'r', encoding='utf-8')
                    current_inode = os.stat(file_path).st_ino
                    continue
            except FileNotFoundError:
                # File was removed during rotation, wait for it to be created again
                logger.debug("Log file deleted. Waiting for recreation.")
                f.close()
                while not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                    logger.warning(f"Waiting for log file to be readable: {file_path}")
                    time.sleep(2.0)
                f = open(file_path, 'r', encoding='utf-8')
                current_inode = os.stat(file_path).st_ino
                continue
            
            # No new data and no rotation, sleep for 50ms and try again
            time.sleep(0.05)
            f.seek(pos)
            continue
            
        line = line.strip()
        if not line:
            continue
            
        try:
            # Parse each line as JSON
            log_data = json.loads(line)
            parsed_entry = {
                "source_ip": log_data.get("source_ip"),
                "timestamp": log_data.get("timestamp"),
                "method": log_data.get("method"),
                "path": log_data.get("path"),
                "status": log_data.get("status"),
                "response_size": log_data.get("response_size")
            }
            yield parsed_entry
        except json.JSONDecodeError:
            # Skip malformed JSON silently with a debug log
            logger.debug(f"Skipping malformed log line: {line}")
        except Exception as e:
            logger.debug(f"Error processing log line: {e}")
