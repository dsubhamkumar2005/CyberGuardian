import pyperclip
import time
import threading

from pipeline import process_url
from url_validator import is_valid_url


def monitor_clipboard():

    last_text = ""

    print("Clipboard monitor started...")
    print("Copy an HTTP/HTTPS URL to test.")

    while True:

        current_text = pyperclip.paste().strip()

        # Show what clipboard actually contains
        if current_text != last_text:

            print("\nClipboard changed!")
            print("Copied text:", repr(current_text))

            last_text = current_text

            if current_text:

                print("Checking URL...")

                if is_valid_url(current_text):

                    print("Valid URL detected!")

                    result = process_url(current_text)

                    print("Processed Result:")
                    print(result)

                else:

                    print("Not a valid HTTP/HTTPS URL.")

        time.sleep(1)


def start_clipboard_monitor():

    thread = threading.Thread(
        target=monitor_clipboard,
        daemon=True
    )

    thread.start()

    return thread


if __name__ == "__main__":
    monitor_clipboard()