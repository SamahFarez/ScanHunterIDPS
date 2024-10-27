import logging

def setup_logging():
    logging.basicConfig(
        filename="hunter_log.txt",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
