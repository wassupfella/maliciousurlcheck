import requests
import tkinter as tk
from urllib.parse import urlparse

API_KEY = "b60ad403241439684393a7c460debfe97c5c936d0957ee668b040c0ff237e275"

def is_malicious_url(url):
    params = {
        "apikey": API_KEY,
        "resource": url,
        "scan": 1
    }

    response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
    result = response.json()

    if result.get("response_code") == 1:
        if result.get("positives", 0) > 0:
            return True
    return False

def check_url():
    url = url_entry.get()
    if is_malicious_url(url):
        result_label.config(text="This URL is potentially malicious.", fg="red")
    else:
        result_label.config(text="This URL seems safe.", fg="green")

# Create the main window
root = tk.Tk()
root.title("Malicious URL Checker")

# Create and place widgets
url_label = tk.Label(root, text="Enter URL:")
url_label.pack(pady=10)

url_entry = tk.Entry(root, width=50)
url_entry.pack()

check_button = tk.Button(root, text="Check URL", command=check_url)
check_button.pack(pady=10)

result_label = tk.Label(root, text="", fg="black")
result_label.pack()

# Start the GUI event loop
root.mainloop()
