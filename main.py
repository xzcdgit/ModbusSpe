import tkinter as tk
from tkinter import filedialog
import ttkbootstrap as ttk
import pandas as pd
import socket
import struct
import time

def calculate_crc(data):
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if (crc & 0x0001) != 0:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

def read_holding_register(ip, port, device_id, register_address, timeout):
    error_info = ''
    for try_time in range(3):  # 如果通讯失败，重试x次
        try:
            # 创建Modbus RTU请求帧
            request = struct.pack('>BBHH', device_id, 0x03, register_address, 0x0001)
            crc = calculate_crc(request)
            request += struct.pack('<H', crc)

            # 通过TCP发送请求
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(request)
                response = s.recv(1024)

            # 解析响应帧
            if len(response) >= 5:
                response_crc = struct.unpack('<H', response[-2:])[0]
                if response[0] == device_id:
                    if calculate_crc(response[:-2]) == response_crc:
                        # 提取寄存器值
                        # register_value = struct.unpack('>H', response[3:5])[0]
                        error_info = "Success"
                        break
                    else:
                        error_info = 'CRC Error'
                else:
                    error_info = 'ID Error'
            else:
                error_info = 'Invalid Response Length'
        except socket.timeout:
            error_info = 'Timeout'
        except Exception as e:
            error_info = f'Error: {e}'
        time.sleep(0.5)
    return error_info

def load_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        data = pd.read_csv(file_path)
        process_data(data)

def process_data(data):
    if not data.empty:
        row = data.iloc[0]
        process_row(row, data.iloc[1:])
    else:
        load_button.config(state=tk.NORMAL)

def process_row(row, remaining_data):
    name = row['Name']
    ip = row['IP']
    port = row['Port']
    device_id = row['DeviceID']
    register_type = row['RegisterType']
    start_address = row['StartAddress']
    timeout = row['Timeout']
    
    if register_type == 'Holding':
        value = read_holding_register(ip, port, device_id, start_address, timeout)
        tree.insert('', tk.END, values=(name, ip, port, device_id, start_address, value))
        tree.update()
        tree.yview_moveto(1)  # 滚动到最新的条目

    if not remaining_data.empty:
        root.after(10, process_data, remaining_data)
    else:
        load_button.config(state=tk.NORMAL)

def clear_output():
    for item in tree.get_children():
        tree.delete(item)

# 创建主窗口
root = ttk.Window(themename="darkly")
root.title("Modbus RTU Checker")
root.geometry("1000x600")

# 创建按钮
load_button = ttk.Button(root, text="Load File", command=load_file, bootstyle="primary")
load_button.pack(pady=10)

clear_button = ttk.Button(root, text="Clear Output", command=clear_output, bootstyle="danger")
clear_button.pack(pady=10)

# 创建 Treeview
columns = ('Name', 'IP', 'Port', 'DeviceID', 'StartAddress', 'Status')
tree = ttk.Treeview(root, columns=columns, show='headings', bootstyle="primary")

# 定义列
tree.column('Name', width=200, anchor=tk.W)
tree.column('IP', width=150, anchor=tk.CENTER)
tree.column('Port', width=100, anchor=tk.CENTER)
tree.column('DeviceID', width=100, anchor=tk.CENTER)
tree.column('StartAddress', width=150, anchor=tk.CENTER)
tree.column('Status', width=150, anchor=tk.CENTER)

# 定义表头
for col in columns:
    tree.heading(col, text=col)

# 添加垂直滚动条
scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=tree.yview)
tree.configure(yscroll=scrollbar.set)

# 放置 Treeview 和滚动条
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 运行主循环
root.mainloop()
 