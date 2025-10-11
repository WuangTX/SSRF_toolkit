"""
Logging System
Hệ thống logging với màu sắc và multiple outputs
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """Custom formatter với màu sắc cho terminal"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    ICONS = {
        'DEBUG': '🔍',
        'INFO': 'ℹ️',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }
    
    def format(self, record):
        # Add color
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[levelname]}"
                f"{self.ICONS.get(levelname, '')} {levelname}"
                f"{self.COLORS['RESET']}"
            )
        
        return super().format(record)

class PentestLogger:
    """Logger chuyên dụng cho pentest toolkit"""
    
    def __init__(self, name: str = "PentestToolkit", 
                 log_level: str = "INFO",
                 log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler với màu sắc
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (không màu)
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def banner(self, text: str):
        """In banner lớn"""
        border = "═" * 60
        self.logger.info(f"\n╔{border}╗")
        self.logger.info(f"║ {text:^58} ║")
        self.logger.info(f"╚{border}╝")
    
    def section(self, text: str):
        """In section header"""
        self.logger.info(f"\n{'─' * 60}")
        self.logger.info(f"📋 {text}")
        self.logger.info(f"{'─' * 60}")
    
    def finding(self, severity: str, message: str):
        """Log security finding"""
        severity_map = {
            'CRITICAL': ('🔥', logging.CRITICAL),
            'HIGH': ('❗', logging.ERROR),
            'MEDIUM': ('⚠️', logging.WARNING),
            'LOW': ('ℹ️', logging.INFO),
            'INFO': ('💡', logging.INFO)
        }
        
        icon, level = severity_map.get(severity.upper(), ('•', logging.INFO))
        self.logger.log(level, f"{icon} [{severity.upper()}] {message}")
    
    def success(self, message: str):
        """Log success message"""
        self.logger.info(f"✅ {message}")
    
    def fail(self, message: str):
        """Log failure message"""
        self.logger.error(f"❌ {message}")
    
    def progress(self, current: int, total: int, message: str):
        """Log progress"""
        percentage = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current / total)
        bar = '█' * filled + '░' * (bar_length - filled)
        self.logger.info(f"[{bar}] {percentage:.1f}% - {message}")
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

# Global logger instance
_global_logger: Optional[PentestLogger] = None

def get_logger(name: str = "PentestToolkit", 
               log_level: str = "INFO",
               log_file: Optional[str] = None) -> PentestLogger:
    """Get or create global logger"""
    global _global_logger
    
    if _global_logger is None:
        # Create log directory if needed
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        _global_logger = PentestLogger(name, log_level, log_file)
    
    return _global_logger

def init_logger(config) -> PentestLogger:
    """Initialize logger từ config"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{config.output_dir}/pentest_{timestamp}.log"
    
    return get_logger(
        name="PentestToolkit",
        log_level=config.log_level,
        log_file=log_file
    )
