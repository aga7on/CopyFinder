import os
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk
import ctypes
import sys
from send2trash import send2trash
import concurrent.futures
import time
import subprocess
import difflib

def print_logo():
    """Выводит ASCII-арт логотип."""
    print(
        """
   ______                             ______    _                __              
  / ____/  ____     ____    __  __   / ____/   (_)   ____   ____/ /  ___    _____
 / /      / __ \   / __ \  / / / /  / /_      / /   / __ \ / __  /  / _ \  / ___/
/ /___   / /_/ /  / /_/ / / /_/ /  / __/     / /   / / / // /_/ /  /  __/ / /    
\____/   \____/  / .___/  \__, /  /_/       /_/   /_/ /_/ \__,_/   \___/ /_/     
                /_/      /____/                                                  
        """
    )

def print_description():
    """Выводит краткое описание утилиты."""
    print("-------------------------------------")
    print("Copy Finder - Утилита для поиска и")
    print("удаления дубликатов файлов.")
    print("Выберите папку. Утилита просканирует её и подпапки.")
    print("На наличие дубликатов :3")
    print("-------------------------------------")

def calculate_hash(file_path):
    """Вычисляет хэш-сумму файла."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def find_duplicates(directory, method='all', progress_callback=None):
    """Находит дубликаты файлов в указанной директории, используя выбранный метод."""
    file_dict = {}
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    processed_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            if method == 'all':
                key = calculate_hash(file_path)
            elif method == 'name':
                key = file
            elif method == 'size':
                key = os.path.getsize(file_path)
            elif method == 'content':
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                key = hash(content)
            
            if key in file_dict:
                file_dict[key].append(file_path)
            else:
                file_dict[key] = [file_path]
            
            processed_count += 1
            if progress_callback:
                progress_callback(processed_count, total_files)

    duplicates = [paths for paths in file_dict.values() if len(paths) > 1]
    return duplicates

class DuplicateFinderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Copy Finder")
        master.geometry("800x600")

        self.setup_ui()
        self.duplicates = []

    def setup_ui(self):
        self.directory_frame = ttk.Frame(self.master, padding="10")
        self.directory_frame.pack(fill=tk.X)

        self.directory_label = ttk.Label(self.directory_frame, text="Выберите директорию:")
        self.directory_label.pack(side=tk.LEFT)

        self.directory_entry = ttk.Entry(self.directory_frame, width=50)
        self.directory_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(10, 10))

        self.browse_button = ttk.Button(self.directory_frame, text="Обзор", command=self.browse_directory)
        self.browse_button.pack(side=tk.RIGHT)

        # Создаем фрейм для кнопок сканирования
        self.scan_frame = ttk.LabelFrame(self.master, text="Сканирование дубликатов", padding="10")
        self.scan_frame.pack(fill=tk.X, padx=10, pady=10)

        # Добавляем кнопки сканирования
        self.scan_all_button = ttk.Button(self.scan_frame, text="Сканировать всё", command=lambda: self.start_scan('all'))
        self.scan_all_button.pack(side=tk.LEFT, padx=5)

        self.scan_name_button = ttk.Button(self.scan_frame, text="По названию", command=lambda: self.start_scan('name'))
        self.scan_name_button.pack(side=tk.LEFT, padx=5)

        self.scan_size_button = ttk.Button(self.scan_frame, text="По размеру", command=lambda: self.start_scan('size'))
        self.scan_size_button.pack(side=tk.LEFT, padx=5)

        self.scan_content_button = ttk.Button(self.scan_frame, text="По тексту", command=lambda: self.start_scan('content'))
        self.scan_content_button.pack(side=tk.LEFT, padx=5)

        self.progress_bar = ttk.Progressbar(self.master, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(pady=10)

        # Создаем Treeview для отображения результатов
        self.result_tree = ttk.Treeview(self.master, columns=('Path', 'Size'), show='headings')
        self.result_tree.heading('Path', text='Путь к файлу')
        self.result_tree.heading('Size', text='Размер')
        self.result_tree.column('Path', width=600)
        self.result_tree.column('Size', width=100)
        self.result_tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Добавляем полосу прокрутки
        scrollbar = ttk.Scrollbar(self.master, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Создаем фрейм для кнопок действий
        self.button_frame = ttk.Frame(self.master, padding="10")
        self.button_frame.pack(fill=tk.X)

        # Добавляем кнопки действий
        self.select_duplicates_button = ttk.Button(self.button_frame, text="Выбрать все дубли", command=self.select_all_duplicates)
        self.select_duplicates_button.pack(side=tk.LEFT, padx=5)

        self.select_all_button = ttk.Button(self.button_frame, text="Выбрать все файлы", command=self.select_all_files)
        self.select_all_button.pack(side=tk.LEFT, padx=5)

        self.move_to_trash_button = ttk.Button(self.button_frame, text="В корзину", command=self.move_to_trash)
        self.move_to_trash_button.pack(side=tk.LEFT, padx=5)

        self.delete_permanently_button = ttk.Button(self.button_frame, text="Удалить безвозвратно", command=self.delete_permanently)
        self.delete_permanently_button.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(self.master, text="")
        self.status_label.pack()

        # Привязываем контекстное меню к дереву
        self.result_tree.bind("<Button-3>", self.show_context_menu)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)

    def start_scan(self, method):
        directory = self.directory_entry.get()
        if not directory:
            self.status_label.config(text="Пожалуйста, выберите директорию")
            return

        self.result_tree.delete(*self.result_tree.get_children())
        self.progress_bar['value'] = 0
        self.disable_scan_buttons()

        self.master.after(100, self.run_scan, directory, method)

    def run_scan(self, directory, method):
        start_time = time.time()
        self.duplicates = find_duplicates(directory, method, self.update_progress)
        end_time = time.time()

        if not self.duplicates:
            self.status_label.config(text="Дубликаты не найдены.")
        else:
            for i, file_paths in enumerate(self.duplicates, 1):
                for j, path in enumerate(file_paths):
                    size = os.path.getsize(path)
                    item_id = self.result_tree.insert('', 'end', values=(path, f"{size} bytes"))
                    if j > 0:  # Не выделяем первый файл в группе (ближайший к корню)
                        self.result_tree.item(item_id, tags=('duplicate',))

        self.result_tree.tag_configure('duplicate', background='light yellow')
        self.status_label.config(text=f"Сканирование завершено за {end_time - start_time:.2f} секунд")
        self.enable_scan_buttons()

    def update_progress(self, current, total):
        progress = int(current / total * 100)
        self.progress_bar['value'] = progress
        self.master.update_idletasks()

    def disable_scan_buttons(self):
        self.scan_all_button['state'] = 'disabled'
        self.scan_name_button['state'] = 'disabled'
        self.scan_size_button['state'] = 'disabled'
        self.scan_content_button['state'] = 'disabled'

    def enable_scan_buttons(self):
        self.scan_all_button['state'] = 'normal'
        self.scan_name_button['state'] = 'normal'
        self.scan_size_button['state'] = 'normal'
        self.scan_content_button['state'] = 'normal'

    def select_all_duplicates(self):
        for item in self.result_tree.get_children():
            if 'duplicate' in self.result_tree.item(item, 'tags'):
                self.result_tree.selection_add(item)

    def select_all_files(self):
        for item in self.result_tree.get_children():
            self.result_tree.selection_add(item)

    def move_to_trash(self):
        selected_items = self.result_tree.selection()
        for item in selected_items:
            file_path = self.result_tree.item(item, 'values')[0]
            try:
                send2trash(file_path)
                self.result_tree.delete(item)
            except Exception as e:
                print(f"Ошибка при перемещении файла {file_path} в корзину: {e}")

    def delete_permanently(self):
        selected_items = self.result_tree.selection()
        for item in selected_items:
            file_path = self.result_tree.item(item, 'values')[0]
            try:
                os.remove(file_path)
                self.result_tree.delete(item)
            except Exception as e:
                print(f"Ошибка при удалении файла {file_path}: {e}")

    def show_context_menu(self, event):
        item = self.result_tree.identify_row(event.y)
        if item:
            self.result_tree.selection_set(item)
            file_path = self.result_tree.item(item, 'values')[0]
            menu = tk.Menu(self.master, tearoff=0)
            menu.add_command(label="Открыть", command=lambda: self.open_file(file_path))
            menu.add_command(label="Открыть расположение файла", command=lambda: self.open_file_location(file_path))
            menu.post(event.x_root, event.y_root)

    def open_file(self, file_path):
        try:
            os.startfile(file_path)
        except Exception as e:
            print(f"Ошибка при открытии файла {file_path}: {e}")

    def open_file_location(self, file_path):
        try:
            subprocess.Popen(f'explorer /select,"{file_path}"')
        except Exception as e:
            print(f"Ошибка при открытии расположения файла {file_path}: {e}")

def is_admin():
    """Проверяет, запущен ли скрипт с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Перезапускает скрипт с правами администратора."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def main():
    if not is_admin():
        run_as_admin()

    root = tk.Tk()
    app = DuplicateFinderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()