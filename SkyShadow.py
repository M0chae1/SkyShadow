#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
import shutil
import sys
import threading
from queue import Queue
import pefile

__version__ = '0.0.1-20240228'

class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ImportDlls(threading.Thread):
    def __init__(self,queue,dll_list):
        threading.Thread.__init__(self)
        self.queue = queue
        self.dll_list = dll_list

    def run(self):
        while not self.queue.empty():
            exe_info = self.queue.get()
            self.check_imported_dlls(exe_info,self.dll_list)

    def get_import_table_for_exe(self,exe_path, exe_name, dll_list):
        exe_full_path = os.path.join(exe_path, exe_name)
        if not os.path.exists(exe_full_path):
            logging.error(f"exe文件未找到 {exe_full_path}")
            return []
        arch="";
        pe = pefile.PE(exe_full_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            logging.error("不支持.NET程序")
            return []

        if pe.OPTIONAL_HEADER.Subsystem == 2:
            logging.error("不支持GUI程序")
            return []

        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            arch = "32-bit"
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = "64-bit"
        import_table = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            if dll_name in dll_list:
                imports = [imp.name.decode('utf-8') if imp.name else str(imp.ordinal) for imp in entry.imports]
                import_table.append((dll_name, imports,arch))
        return import_table

    def generate_export_functions(self,exe_info, dll, arch):
        exe_name, exe_path = exe_info
        destination_directory = os.path.join("dllInject", f"{arch}_{exe_name}")

        try:
            os.makedirs(destination_directory, exist_ok=True)
            destination_file = os.path.join(destination_directory, exe_name)
            shutil.copyfile(os.path.join(exe_path, exe_name), destination_file)

            dll_name = dll[0].replace(".dll", ".cpp")
            with open(os.path.join(destination_directory, dll_name), "w") as f:
                for item in dll[1]:
                    payload = 'extern "C" __declspec(dllexport) int ' + item + '() { return 0; }\n'
                    f.write(payload)

            logging.info(f"{dll_name} 导出函数生成成功")
        except PermissionError:
            logging.error("目录权限被拒绝！无法创建目录或写入文件")
        except Exception as e:
            logging.error(f"发生了错误, Error: {e}")

    def check_imported_dlls(self,exe_info, dll_list):
        exe_name, exe_path = exe_info
        import_table = self.get_import_table_for_exe(exe_path, exe_name,dll_list)
        if len(import_table)>0:
            for dll in import_table:
                dll_name = dll[0]
                arch = dll[2]
                dll_path = os.path.join(exe_path, dll_name)
                if os.path.exists(dll_path) and dll_name in dll_list:
                    self.generate_export_functions(exe_info,dll,arch)
def scan_directory(path):
    dll_list = []
    queue = Queue()
    try:
        for file_name in os.listdir(path):
            file_path = os.path.join(path, file_name)
            if os.path.isdir(file_path):
                scan_directory(file_path)
            elif file_name.endswith('.dll'):
                dll_list.append(file_name)
            elif file_name.endswith('.exe'):
                # exe_list.append((file_name, path))
                queue.put((file_name, path))

        threads = []
        for i in range(5):
            threads.append(ImportDlls(queue, dll_list))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    except FileNotFoundError:
        logging.error(f"路径未找到 path: {path}")
    except PermissionError:
        logging.error(f"路径不允许访问 path: {path}")
    except Exception as e:
        logging.error(f"发生了错误, Error: {e}")



def main():
    print(f'\n')
    print(
        f'{Bcolors.Green}▌║█║▌│║▌│║▌║▌█║ {Bcolors.Red}SkyShadow{Bcolors.White} v{__version__}{Bcolors.Green} ▌│║▌║▌│║║▌█║▌║█{Bcolors.Endc}\n')

    if (len(sys.argv) == 2):
        scan_directory(sys.argv[1])
    else:
        print('Usage: python SkyShadow.py "D:/"')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{__name__.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')