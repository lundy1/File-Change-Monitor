import os
import time
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileMonitor(FileSystemEventHandler):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.last_event_time = {}

    def should_process_event(self, event_path):
        current_time = datetime.now().timestamp()
        last_time = self.last_event_time.get(event_path, 0)
        if current_time - last_time > 0.1:
            self.last_event_time[event_path] = current_time
            return True
        return False

    def process_event(self, event, event_type):
        if not self.should_process_event(event.src_path):
            return
        try:
            file_info = self.get_file_info(event.src_path)
            responsible_app = self.get_responsible_app(event.src_path)
            event_data = (
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                event_type,
                event.src_path,
                file_info['size'],
                file_info['type'],
                file_info['last_accessed'],
                responsible_app
            )
            self.app.queue.put(event_data)
            self.app.root.event_generate("<<FileEvent>>")
        except Exception as e:
            print(f"Error processing event: {e}")

    def get_file_info(self, file_path):
        try:
            if os.path.exists(file_path):
                return {
                    'size': os.path.getsize(file_path) if os.path.isfile(file_path) else "N/A",
                    'type': os.path.splitext(file_path)[1] if os.path.isfile(file_path) else "Folder",
                    'last_accessed': datetime.fromtimestamp(os.path.getatime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                }
        except (FileNotFoundError, OSError):
            pass
        return {
            'size': "N/A",
            'type': "Unknown",
            'last_accessed': "N/A"
        }

    def get_responsible_app(self, file_path):
        try:
            for proc in psutil.process_iter(['name', 'open_files']):
                try:
                    files = proc.open_files()
                    if any(file_path in str(f.path) for f in files):
                        return proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return "Unknown"

    def on_created(self, event):
        self.process_event(event, "Created")

    def on_deleted(self, event):
        self.process_event(event, "Deleted")

    def on_modified(self, event):
        self.process_event(event, "Modified")

    def on_moved(self, event):
        self.process_event(event, "Moved")
        
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("File Change Monitor")
        self.queue = Queue()
        self.stop_flag = False
        self.autoscroll = True
        self.create_widgets()
        self.directory_to_watch = ""
        self.selected_apps = set()

    def create_widgets(self):
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.grid(row=0, column=0, sticky="ew")

        self.directory_label = ttk.Label(control_frame, text="Directory to Monitor:")
        self.directory_label.grid(row=0, column=0, padx=5, pady=5)
        self.directory_entry = ttk.Entry(control_frame, width=50)
        self.directory_entry.grid(row=0, column=1, padx=5, pady=5)
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)

        self.app_label = ttk.Label(control_frame, text="Select Applications to Monitor:")
        self.app_label.grid(row=1, column=0, padx=5, pady=5)
        self.app_listbox = tk.Listbox(control_frame, selectmode=tk.MULTIPLE, height=10)
        self.app_listbox.grid(row=1, column=1, padx=5, pady=5)

        self.refresh_button = ttk.Button(control_frame, text="Refresh Applications", command=self.refresh_apps)
        self.refresh_button.grid(row=1, column=2, padx=5, pady=5)
        self.refresh_apps()

        columns = ('Time', 'Event', 'Path', 'Size', 'Type', 'Last Accessed', 'Human')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Event', text='Event')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Size', text='Size (bytes)')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Last Accessed', text='Last Accessed')
        self.tree.heading('Human', text='Human Action')

        self.tree.column('Time', width=150)
        self.tree.column('Event', width=100)
        self.tree.column('Path', width=400)
        self.tree.column('Size', width=100)
        self.tree.column('Type', width=100)
        self.tree.column('Last Accessed', width=150)
        self.tree.column('Human', width=100)

        self.tree.grid(row=2, column=0, sticky='nsew')

        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=2, column=1, sticky='ns')

        self.tree.bind("<MouseWheel>", self.on_scroll)
        self.tree.bind("<Button-4>", self.on_scroll)  # For Linux systems
        self.tree.bind("<Button-5>", self.on_scroll)  # For Linux systems
        self.tree.bind("<Motion>", self.on_scroll_stop)

        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def refresh_apps(self):
        self.app_listbox.delete(0, tk.END)
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            self.app_listbox.insert(tk.END, proc.info['name'])

    def start_monitoring(self):
        self.directory_to_watch = self.directory_entry.get()
        self.selected_apps = set(self.app_listbox.get(i) for i in self.app_listbox.curselection())

        if self.directory_to_watch:
            self.stop_flag = False
            self.tree.insert('', tk.END, values=(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "Info", f"Starting to monitor: {self.directory_to_watch}", "", "", "", ""))
            self.watcher_thread = Thread(target=self.run_watcher)
            self.watcher_thread.daemon = True
            self.watcher_thread.start()
        else:
            messagebox.showerror("Error", "Please enter a directory to monitor.")

    def run_watcher(self):
        handler = CustomHandler(self)
        observer = Observer()
        observer.schedule(handler, self.directory_to_watch, recursive=True)
        observer.start()
        try:
            while not self.stop_flag:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.stop()
        observer.join()

    def stop_monitoring(self):
        self.stop_flag = True
        self.tree.insert('', tk.END, values=(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "Info", "Stopped monitoring.", "", "", "", ""))

    def handle_watchdog_event(self, event):
        event_type, watchdog_event = self.queue.get()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        file_size = os.path.getsize(watchdog_event.src_path) if os.path.isfile(watchdog_event.src_path) else "N/A"
        file_type = os.path.splitext(watchdog_event.src_path)[1] if os.path.isfile(watchdog_event.src_path) else "Folder"
        last_accessed = datetime.fromtimestamp(os.path.getatime(watchdog_event.src_path)).strftime('%Y-%m-%d %H:%M:%S') if os.path.isfile(watchdog_event.src_path) else "N/A"

        if self.is_related_to_selected_apps():
            self.tree.insert('', tk.END, values=(timestamp, event_type, watchdog_event.src_path, file_size, file_type, last_accessed, "Unknown"))
            if self.autoscroll:
                self.tree.yview_moveto(1)

    def is_related_to_selected_apps(self):
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if proc.info['name'] in self.selected_apps:
                return True
        return False

    def notify(self, event, event_type):
        self.queue.put((event_type, event))
        self.root.event_generate("<<WatchdogEvent>>", when="tail")

    def on_scroll(self, event):
        self.autoscroll = False

    def on_scroll_stop(self, event):
        if self.tree.yview()[1] == 1.0:
            self.autoscroll = True

    def mainloop(self):
        self.root.bind("<<WatchdogEvent>>", self.handle_watchdog_event)
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
