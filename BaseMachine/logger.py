"""
Unified Logging System for WorkFlow Framework
Provides consistent logging configuration across all modules.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output."""
    
    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
    }
    
    def format(self, record):
        """Format log record with color coding."""
        # Add color to level name
        level_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
        
        # Add color to module name for better readability
        if hasattr(record, 'module'):
            record.module = f"{Fore.CYAN}{record.module}{Style.RESET_ALL}"
        
        return super().format(record)


class WorkflowLogger:
    """
    Unified logger for the workflow framework.
    Provides consistent logging across all modules with proper formatting and colors.
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """Singleton pattern to ensure only one logger configuration."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the logger configuration."""
        if self._initialized:
            return
        
        self._setup_logging()
        self._initialized = True
    
    def _setup_logging(self):
        """Setup the unified logging configuration."""
        # Get root logger
        root_logger = logging.getLogger()
        
        # Clear any existing handlers to avoid duplicates
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Set logging level
        root_logger.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Create colored formatter for console
        console_format = (
            f"{Fore.WHITE}[%(asctime)s]{Style.RESET_ALL} "
            f"{Fore.CYAN}[%(name)s]{Style.RESET_ALL} "
            f"[%(levelname)s] "
            f"%(message)s"
        )
        console_formatter = ColoredFormatter(
            console_format,
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        # Add handler to root logger
        root_logger.addHandler(console_handler)
        
        # Optionally create file handler for persistent logging
        self._setup_file_logging()
    
    def _setup_file_logging(self):
        """Setup file logging for persistent logs."""
        try:
            # Create logs directory if it doesn't exist
            log_dir = Path('logs')
            log_dir.mkdir(exist_ok=True)
            
            # Create file handler with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = log_dir / f'workflow_{timestamp}.log'
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)  # File logs can be more verbose
            
            # Create plain formatter for file (no colors)
            file_format = (
                '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
            )
            file_formatter = logging.Formatter(
                file_format,
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            
            # Add file handler to root logger
            logging.getLogger().addHandler(file_handler)
            
        except Exception as e:
            # If file logging fails, continue with console logging only
            print(f"Warning: Could not setup file logging: {e}")
    
    @staticmethod
    def get_logger(name=None):
        """
        Get a logger instance for a specific module.
        
        Args:
            name: Logger name (usually __name__ or module name)
            
        Returns:
            Configured logger instance
        """
        # Ensure the unified logger is initialized
        WorkflowLogger()
        
        if name is None:
            name = 'workflow'
        
        # Clean up the name for better readability
        if name.startswith('WorkflowTemplate.'):
            name = name.replace('WorkflowTemplate.', 'WF.')
        elif name.startswith('BaseMachine.'):
            name = name.replace('BaseMachine.', 'BM.')
        
        return logging.getLogger(name)
    
    @staticmethod
    def log_step_start(step_name, description=""):
        """Log the start of a workflow step with consistent formatting."""
        logger = WorkflowLogger.get_logger('workflow')
        separator = "=" * 60
        logger.info(f"\n{Fore.CYAN}{separator}")
        logger.info(f"{Fore.CYAN}🚀 Starting: {step_name}")
        if description:
            logger.info(f"{Fore.CYAN}📝 Description: {description}")
        logger.info(f"{Fore.CYAN}{separator}{Style.RESET_ALL}")
    
    @staticmethod
    def log_step_complete(step_name, result=None):
        """Log the completion of a workflow step."""
        logger = WorkflowLogger.get_logger('workflow')
        logger.info(f"{Fore.GREEN}✅ Completed: {step_name}{Style.RESET_ALL}")
        if result:
            logger.info(f"{Fore.WHITE}📊 Result: {result}{Style.RESET_ALL}")
    
    @staticmethod
    def log_step_error(step_name, error):
        """Log a workflow step error with proper formatting."""
        logger = WorkflowLogger.get_logger('workflow')
        logger.error(f"{Fore.RED}❌ Failed: {step_name}")
        logger.error(f"{Fore.RED}💥 Error: {error}{Style.RESET_ALL}")
    
    @staticmethod
    def log_workflow_summary(total_steps, completed_steps, errors=None):
        """Log a workflow execution summary."""
        logger = WorkflowLogger.get_logger('workflow')
        separator = "=" * 60
        logger.info(f"\n{Fore.MAGENTA}{separator}")
        logger.info(f"{Fore.MAGENTA}📋 Workflow Summary")
        logger.info(f"{Fore.MAGENTA}{separator}")
        logger.info(f"{Fore.WHITE}📊 Total Steps: {total_steps}")
        logger.info(f"{Fore.GREEN}✅ Completed: {completed_steps}")
        if errors:
            logger.info(f"{Fore.RED}❌ Errors: {len(errors)}")
            for error in errors:
                logger.error(f"{Fore.RED}   • {error}")
        success_rate = (completed_steps / total_steps * 100) if total_steps > 0 else 0
        logger.info(f"{Fore.CYAN}📈 Success Rate: {success_rate:.1f}%")
        logger.info(f"{Fore.MAGENTA}{separator}{Style.RESET_ALL}")


# Convenience functions for easy access
def get_logger(name=None):
    """Get a logger instance - convenience function."""
    return WorkflowLogger.get_logger(name)


def setup_logging():
    """Initialize the unified logging system - convenience function."""
    WorkflowLogger()


# Initialize logging when module is imported
setup_logging() 