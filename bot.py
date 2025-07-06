import logging

# --- Main moderation/chat logs to chat_log.txt ---
logging.basicConfig(
    filename="chat_log.txt",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)

import yaml
import threading
import sys
import os
import json
import requests

from twitch_auth import TwitchOAuthTokenManager
from irc_client import run_irc_forever
from moderation import message_queue, batch_worker, run_worker, loss_report, configure_limits

def load_config():
    if not os.path.exists("config.yaml"):
        print("Missing config.yaml! Exiting.")
        sys.exit(1)
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def main():
    config = load_config()

    # --- Twitch/Ollama setup ---
    twitch = config["twitch"]
    ollama_url = config.get("ollama_url", "http://localhost:11434")
    model = config.get("model", "llama3")
    batch_interval = config.get("batch_interval", 2)
    moderation_timeout = config.get("moderation_timeout", 60)
    use_completion = config.get("use_completion", False)
    max_openai_content_size = config.get("max_openai_content_size", 256000)
    max_rate_limit_retries = config.get("max_rate_limit_retries", 3)
    channel = twitch["channel"]

    # --- Token manager ---
    token_manager = TwitchOAuthTokenManager(
        client_id=twitch["client_id"],
        client_secret=twitch["client_secret"]
    )

    configure_limits(max_openai_content_size, max_rate_limit_retries)

    # --- Moderation batch and run workers (threads) ---
    stop_event = threading.Event()
    batch_thread = threading.Thread(
        target=batch_worker,
        args=(
            stop_event,
            ollama_url,
            model,
            channel,
            twitch["client_id"],
            token_manager,
            batch_interval
        ),
        daemon=True
    )
    batch_thread.start()

    run_thread = threading.Thread(
        target=run_worker,
        args=(
            stop_event,
            ollama_url,
            model,
            twitch["client_id"],
            token_manager,
            moderation_timeout,
            use_completion
        ),
        daemon=True
    )
    run_thread.start()

    try:
        print("[BOT] Starting IRC loop...")
        run_irc_forever(config, token_manager, message_queue)
    except KeyboardInterrupt:
        print("\n[BOT] Exiting on user interrupt...")
    finally:
        stop_event.set()
        batch_thread.join(timeout=10)
        run_thread.join(timeout=10)
        loss_report()

if __name__ == "__main__":
    main()