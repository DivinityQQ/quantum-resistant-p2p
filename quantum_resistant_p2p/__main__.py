"""
Main entry point for the post-quantum P2P application.
"""

import sys
import asyncio
import logging
import os
import platform
import signal
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from qasync import QEventLoop

from .ui import MainWindow


# Configure logging
def setup_logging():
    """Set up logging for the application."""
    log_dir = Path.home() / ".quantum_resistant_p2p" / "logs"
    log_dir.mkdir(exist_ok=True, parents=True)
    
    # Change from app.log to a normal system log
    log_file = log_dir / "system.log"
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Set specific levels for some loggers
    logging.getLogger("quantum_resistant_p2p.networking").setLevel(logging.INFO)
    logging.getLogger("quantum_resistant_p2p.crypto").setLevel(logging.INFO)
    
    # Create a logger for this module
    logger = logging.getLogger(__name__)
    logger.info("Logging initialized")
    
    return logger


def main():
    """Main entry point for the application."""
    # Set up logging
    logger = setup_logging()
    
    try:
        # Create the application
        app = QApplication(sys.argv)
        app.setApplicationName("Quantum Resistant P2P")
        app.setOrganizationName("DivinityQQ")
        app.setOrganizationDomain("DivinityQQ@gmail.com")
        
        # Create the event loop
        loop = QEventLoop(app)
        asyncio.set_event_loop(loop)
        
        # Handle signals differently based on platform
        if platform.system() != "Windows":
            # Unix-like systems can use add_signal_handler
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(loop)))
        else:
            # Windows needs a different approach
            # Define the handler for Windows
            def win_handler(signum, frame):
                asyncio.create_task(shutdown(loop))
                
            # Register the handler for CTRL+C (SIGINT) on Windows
            signal.signal(signal.SIGINT, win_handler)
        
        # Create and show the main window
        main_window = MainWindow()
        main_window.show()
        
        logger.info("Application started")
        
        # Run the event loop
        with loop:
            loop.run_forever()
        
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        return 1
    
    logger.info("Application exiting")
    return 0


async def shutdown(loop):
    """Shutdown the application gracefully.
    
    Args:
        loop: The event loop
    """
    logger = logging.getLogger(__name__)
    logger.info("Shutting down gracefully...")
    
    # Get all tasks
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    
    # Cancel all tasks
    for task in tasks:
        task.cancel()
    
    # Wait for all tasks to complete
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    
    # Stop the event loop
    loop.stop()


if __name__ == "__main__":
    sys.exit(main())