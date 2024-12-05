import tkinter as tk
from tkinter import filedialog
import pandas as pd
import socket
import struct

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

def read_holding_register(ip, port, device_id, register_address):
    error_info = ''
    for try_time in range(3):
        try:
            # 创建Modbus RTU请求帧
            request = struct.pack('>BBHH', device_id, 0x03, register_address, 0x0001)
            crc = calculate_crc(request)
            request += struct.pack('<H', crc)

            # 通过TCP发送请求
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1) 
                s.connect((ip, port))
                s.sendall(request)
                response = s.recv(1024)

            # 解析响应帧
            if len(response) >= 5:
                response_crc = struct.unpack('<H', response[-2:])[0]
                if calculate_crc(response[:-2]) == response_crc:
                    # 提取寄存器值
                    #register_value = struct.unpack('>H', response[3:5])[0]
                    error_info = "Success"
                    break
                else:
                    error_info = 'CRC Error'
            else:
                error_info = 'Invalid Response Length'
        except socket.timeout:
            error_info = 'Timeout'
        except Exception as e:
            error_info = f'Error: {e}'
    return error_info
        

def load_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        data = pd.read_csv(file_path)
        for index, row in data.iterrows():
            name = row['Name']
            ip = row['IP']
            port = row['Port']
            device_id = row['DeviceID']
            register_type = row['RegisterType']
            start_address = row['StartAddress']
            if register_type == 'Holding':
                value = read_holding_register(ip, port, device_id, start_address)
                result_text.insert(tk.END, f'Name {name} at {ip}:{port} {device_id}- Register {start_address}: {value}\n')
                result_text.update_idletasks()  # 刷新界面

# 创建主窗口
root = tk.Tk()
root.title("Modbus RTU Checker")

# 创建按钮和文本框
load_button = tk.Button(root, text="Load File", command=load_file)
load_button.pack(pady=10)

result_text = tk.Text(root, height=20, width=80)
result_text.pack(pady=10)

# 运行主循环
root.mainloop()
