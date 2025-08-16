#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深澜(Srun)校园网自动认证脚本
适用于人民大学校园网认证系统
"""

import requests
import json
import time
import hashlib
import hmac
import base64
import re
import logging
import os
from urllib.parse import urlencode

try:
    import yaml
except ImportError:
    yaml = None


def setup_logging():
    """配置日志系统"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"srun_auth_{time.strftime('%Y%m%d')}.log")
    
    # 配置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 创建logger
    logger = logging.getLogger('srun_auth')
    logger.setLevel(logging.DEBUG)
    
    # 防止重复添加handler
    if logger.handlers:
        logger.handlers.clear()
    
    # 文件handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # 控制台handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


def load_config():
    """加载配置文件"""
    config_files = ['config.yaml', 'config.yml']
    
    for config_file in config_files:
        if os.path.exists(config_file):
            if yaml is None:
                raise ImportError("需要安装 PyYAML: pip install PyYAML")
            
            with open(config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
    
    return {}


class SrunAuth:
    def __init__(self, username=None, password=None, ip=None, ac_id="1", domain=""):
        # 加载配置文件
        config = load_config()
        
        # 从参数、环境变量或配置文件读取凭据
        self.username = username or os.getenv('SRUN_USERNAME') or config.get('username')
        self.password = password or os.getenv('SRUN_PASSWORD') or config.get('password')
        
        if not self.username or not self.password:
            raise ValueError("必须提供用户名和密码，可通过:\n1. 参数传入\n2. 环境变量 SRUN_USERNAME, SRUN_PASSWORD\n3. config.yaml 配置文件")
        
        self.ip = ip or config.get('ip') or self.get_local_ip()
        self.ac_id = ac_id if ac_id != "1" else config.get('ac_id', "1")
        self.domain = domain or config.get('domain', "")
        self.base_url = "https://go.ruc.edu.cn/cgi-bin"
        
        # 初始化logger
        self.logger = logging.getLogger('srun_auth')
        self.logger.info(f"初始化认证客户端 - 用户: {self.username}, IP: {self.ip}, AC_ID: {self.ac_id}")
        
        # 从源码中提取的base64字母表
        self.base64_alpha = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
        
        # 设备信息（从配置文件读取或使用默认值）
        device_config = config.get('device', {})
        self.device_info = {
            'device': device_config.get('name', 'Windows 10'),
            'platform': device_config.get('platform', 'Windows')
        }

    def get_local_ip(self):
        """获取本机IP地址"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if hasattr(self, 'logger'):
                self.logger.debug(f"获取到本机IP: {ip}")
            return ip
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.warning(f"无法获取本机IP，使用默认IP: {e}")
            else:
                print("无法获取本机IP，使用默认IP")
            return "127.0.0.1"

    def custom_base64_encode(self, data):
        """使用自定义字母表的base64编码"""
        # 标准base64编码
        standard_encoded = base64.b64encode(data.encode()).decode()
        
        # 标准和自定义字母表
        standard_alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        custom_alpha = self.base64_alpha
        
        # 字符替换
        result = ''
        for char in standard_encoded:
            if char in standard_alpha:
                index = standard_alpha.index(char)
                result += custom_alpha[index]
            else:
                result += char
        
        return result

    def sha1(self, text):
        """SHA1加密"""
        return hashlib.sha1(text.encode()).hexdigest()

    def hmac_md5(self, password, challenge):
        """根据源码实现的特殊MD5加密"""
        
        def js_md5_hex(s:str)->str:
            # 等价于 JS 的 p(n) = g(m(n)) = hex(MD5(UTF8(n)))
            return hashlib.md5(s.encode('utf-8')).hexdigest()

        def js_hmac_md5_hex(key:str, msg:str)->str:
            # 等价于 JS 的 C(t,n) = g(s(t,n)) = hex(HMAC_MD5(key=UTF8(t), msg=UTF8(n)))
            return hmac.new(key.encode('utf-8'), msg.encode('utf-8'), hashlib.md5).hexdigest()

        def A_py(n:str, t:str|None=None, r=None)->str:
            # 对应 JS: return t ? (r ? s(t,n) : C(t,n)) : (r ? m(n) : p(n))
            # 这里 r 为 undefined/falsy，因此只在 C(t,n) 与 p(n) 之间二选一
            if t:  # 非空字符串视为 True
                return js_hmac_md5_hex(t, n)   # HMAC-MD5(key=token, msg=password)
            else:
                return js_md5_hex(n)           # 纯 MD5(password)

        return A_py(password, challenge)

    def encode_user_info(self,info_dict, token):
        """
        精确复现JavaScript _encodeUserInfo函数
        基于JavaScript运行结果进行精确匹配
        """
        
        def custom_base64_encode(data):
            """使用自定义字母表的base64编码"""
            # 关键：使用latin1编码处理二进制数据
            if isinstance(data, str):
                data_bytes = data.encode('latin1')
            else:
                data_bytes = data
            
            standard_encoded = base64.b64encode(data_bytes).decode()
            
            standard_alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            custom_alpha = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
            
            result = ''
            for char in standard_encoded:
                if char in standard_alpha:
                    index = standard_alpha.index(char)
                    result += custom_alpha[index]
                else:
                    result += char
            
            return result
        
        
        def s(a, b):
            """精确复现JavaScript的s函数"""
            c = len(a)
            v = []
            for i in range(0, c, 4):
                index = i >> 2
                # 确保数组足够长
                while len(v) <= index:
                    v.append(0)
                    # v.append('0')
                
                # JavaScript charCodeAt对越界返回NaN，在位运算中变成0
                def safe_char_code(s, idx):
                    return ord(s[idx]) if idx < len(s) else 0
                
                val = (safe_char_code(a, i) | 
                        (safe_char_code(a, i + 1) << 8) | 
                        (safe_char_code(a, i + 2) << 16) | 
                        (safe_char_code(a, i + 3) << 24))
                
                # JavaScript的32位有符号整数处理
                v[index] = val if val < 0x80000000 else val - 0x100000000
                # v[index] = str(v[index])
            
            if b:
                # v.append(str(c))
                v.append(c)
            return v

        def l(a, b):
            """精确复现JavaScript的l函数"""
            d = len(a)
            c = (d - 1) << 2
            
            if b:
                m = a[d - 1]
                if m < c - 3 or m > c:
                    return None
                c = m
            
            # 创建副本避免修改原数组
            result_parts = []
            for i in range(d):
                val = a[i]
                # 确保是32位无符号整数
                val = val & 0xFFFFFFFF
                
                result_parts.append(
                    chr(val & 0xFF) +
                    chr((val >> 8) & 0xFF) +
                    chr((val >> 16) & 0xFF) +
                    chr((val >> 24) & 0xFF)
                )
            
            result = ''.join(result_parts)
            return result[:c] if b else result

        def encode(str_data, key):
            """精确复现JavaScript的encode函数（XXTEA加密）"""
            if str_data == '':
                return ''
                
            v = s(str_data, True)
            k = s(key, False)
            
            # JavaScript: if(k.length<4)k.length=4;
            if len(k) < 4:
                k.extend([0] * (4 - len(k)))
            k = k[:4]  # 确保只有4个元素
            
            n = len(v) - 1
            if n < 1:
                return l(v, False)
                
            z = v[n]
            y = v[0]
            
            # JavaScript源码中的常量（作为有符号32位整数）
            c = (0x86014019 | 0x183639A0)
            if c >= 0x80000000:
                c -= 0x100000000
                
            q = 6 + 52 // (n + 1)
            d = 0
            
            while q > 0:
                # 精确复现JavaScript的位运算
                d = ((d + c) & (0x8CE0D9BF | 0x731F2640)) & 0xFFFFFFFF
                if d >= 0x80000000:
                    d -= 0x100000000
                    
                e = (d >> 2) & 3
                
                for p in range(n):
                    y = v[p + 1]
                    
                    # 使用无符号右移
                    m = ((z & 0xFFFFFFFF) >> 5) ^ ((y << 2) & 0xFFFFFFFF)
                    m = (m + (((y & 0xFFFFFFFF) >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y))) & 0xFFFFFFFF
                    m = (m + ((k[(p & 3) ^ e] ^ z) & 0xFFFFFFFF)) & 0xFFFFFFFF
                    
                    z = v[p] = ((v[p] + m) & (0xEFB8D130 | 0x10472ECF)) & 0xFFFFFFFF
                    if z >= 0x80000000:
                        z = v[p] = z - 0x100000000
                
                y = v[0]
                m = ((z & 0xFFFFFFFF) >> 5) ^ ((y << 2) & 0xFFFFFFFF)
                m = (m + (((y & 0xFFFFFFFF) >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y))) & 0xFFFFFFFF
                m = (m + ((k[(n & 3) ^ e] ^ z) & 0xFFFFFFFF)) & 0xFFFFFFFF
                
                z = v[n] = ((v[n] + m) & (0xBB390742 | 0x44C6F8BD)) & 0xFFFFFFFF
                if z >= 0x80000000:
                    z = v[n] = z - 0x100000000
                
                q -= 1
            
            return l(v, False)
        
        # 主流程
        info_str = json.dumps(info_dict, separators=(',', ':'))
        encrypted_str = encode(info_str, token)
        encoded = custom_base64_encode(encrypted_str)
        
        return '{SRBX1}' + encoded

    def generate_callback(self):
        """生成jQuery callback"""
        import random
        random_num = str(random.random())[2:]
        timestamp = str(int(time.time() * 1000))
        return f"jQuery{random_num}_{timestamp}"

    def get_challenge(self):
        """获取认证challenge"""
        self.logger.debug("开始获取认证challenge")
        callback = self.generate_callback()
        timestamp = str(int(time.time() * 1000))
        
        params = {
            'callback': callback,
            'username': self.username,
            'ip': self.ip,
            '_': timestamp
        }
        
        url = f"{self.base_url}/get_challenge?" + urlencode(params)
        self.logger.debug(f"Challenge请求URL: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            self.logger.debug(f"Challenge响应状态码: {response.status_code}")
            self.logger.debug(f"Challenge响应内容: {response.text}")
            
            # 解析JSONP响应
            content = response.text
            # 提取JSON部分
            json_match = re.search(r'jQuery\d+_\d+\((.*)\)', content)
            if json_match:
                json_str = json_match.group(1)
                data = json.loads(json_str)
                challenge = data.get('challenge', '')
                if challenge:
                    self.logger.info(f"成功获取challenge: {challenge}")
                    return challenge
                else:
                    self.logger.error("响应中没有challenge字段")
                    return None
            else:
                self.logger.error("获取challenge失败：响应格式错误")
                return None
        except Exception as e:
            self.logger.error(f"获取challenge失败: {e}")
            return None

    def login(self):
        """执行登录"""
        self.logger.info(f"开始认证用户: {self.username}")
        self.logger.info(f"使用IP: {self.ip}")
        
        # 1. 获取challenge
        challenge = self.get_challenge()
        if not challenge:
            self.logger.error("无法获取challenge，认证失败")
            return False
        
        # 2. 准备登录参数
        callback = self.generate_callback()
        
        # 使用原始用户名（根据抓包示例，不需要域名后缀）
        full_username = self.username
        
        # 密码加密
        hmd5 = self.hmac_md5(self.password, challenge)
        # print(self.hmac_md5(self.password, '287e002c0354a850c5fcc6b4ca08e909c4bed67a825d76b5742674c2ac5ad5da'))
        self.logger.debug(f"密码MD5: {hmd5}")
        
        # 用户信息编码 - 注意这里也要使用完整用户名
        user_info = {
            'username': full_username,
            'password': self.password,
            'ip': str(self.ip),
            'acid': str(self.ac_id),  # 保持与JavaScript一致，使用数字类型
            'enc_ver': 'srun_bx1'
        }
        
        info_encoded = self.encode_user_info(user_info, challenge)
        self.logger.debug(f"用户信息编码: {info_encoded}")
        self.logger.debug(f"用户信息JSON: {json.dumps(user_info, separators=(',', ':'))}")
        self.logger.debug(f"Challenge: {challenge}")
        
        # 计算校验和 - 使用完整用户名
        str_for_hash = (challenge + full_username + 
                       challenge + hmd5 + 
                       challenge + str(self.ac_id) + 
                       challenge + self.ip + 
                       challenge + "200" + 
                       challenge + "1" + 
                       challenge + info_encoded)
        
        chksum = self.sha1(str_for_hash)
        self.logger.debug(f"校验和: {chksum}")
        
        # 3. 构建登录请求 - 使用完整用户名
        login_params = {
            'callback': callback,
            'action': 'login',
            'username': full_username,
            'password': '{MD5}' + hmd5,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'chksum': chksum,
            'info': info_encoded,
            'n': '200',
            'type': '1',
            'os': self.device_info['device'],
            'name': self.device_info['platform'],
            'double_stack': '0'
        }
        
        url = f"{self.base_url}/srun_portal?" + urlencode(login_params)
        self.logger.debug(f"登录请求URL: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            content = response.text
            self.logger.debug(f"登录响应状态码: {response.status_code}")
            self.logger.debug(f"登录响应内容: {content}")
            
            # 解析JSONP响应
            json_match = re.search(r'jQuery\d+_\d+\((.*)\)', content)
            if json_match:
                json_str = json_match.group(1)
                data = json.loads(json_str)
                
                if 'error' in data and data['error'] != 'ok':
                    self.logger.error(f"登录失败: {data.get('error')}, {data.get('error_msg')}, {data.get('ecode')}")
                    self.logger.error(f"完整响应数据: {data}")
                    return False
                else:
                    success_msg = data.get('suc_msg', '认证成功')
                    self.logger.info(f"登录成功: {success_msg}")
                    return True
            else:
                self.logger.error("登录失败：响应格式错误")
                return False
                
        except Exception as e:
            self.logger.error(f"登录请求失败: {e}")
            return False

    def logout(self):
        """注销登录"""
        self.logger.info("正在注销...")
        
        callback = self.generate_callback()
        full_username = self.username
        
        logout_params = {
            'callback': callback,
            'action': 'logout',
            'username': full_username,
            'ip': self.ip,
            'ac_id': self.ac_id
        }
        
        url = f"{self.base_url}/srun_portal?" + urlencode(logout_params)
        self.logger.debug(f"注销请求URL: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            content = response.text
            self.logger.debug(f"注销响应状态码: {response.status_code}")
            self.logger.debug(f"注销响应内容: {content}")
            
            json_match = re.search(r'jQuery\d+_\d+\((.*)\)', content)
            if json_match:
                json_str = json_match.group(1)
                data = json.loads(json_str)
                success_msg = data.get('suc_msg', '注销完成')
                self.logger.info(f"注销成功: {success_msg}")
                return True
            else:
                self.logger.error("注销失败：响应格式错误")
                return False
                
        except Exception as e:
            self.logger.error(f"注销请求失败: {e}")
            return False

    def check_online_status(self):
        """检查在线状态并返回详细信息"""
        self.logger.debug("开始检查在线状态")
        try:
            callback = self.generate_callback()
            timestamp = str(int(time.time() * 1000))
            params = {
                'callback': callback,
                'user_name': self.username,
                '_': timestamp
            }
            
            url = f"{self.base_url}/rad_user_info?" + urlencode(params)
            self.logger.debug(f"状态检查请求URL: {url}")
            response = requests.get(url, timeout=5)
            self.logger.debug(f"状态检查响应状态码: {response.status_code}")
            self.logger.debug(f"状态检查响应内容: {response.text}")
            
            json_match = re.search(r'jQuery\d+_\d+\((.*)\)', response.text)
            if json_match:
                data = json.loads(json_match.group(1))
                result = self.parse_user_info(data)
                if result['online']:
                    self.logger.info(f"用户在线状态: {result['status_message']}")
                else:
                    self.logger.warning(f"用户离线状态: {result.get('error', result.get('status_message', '未知'))}")
                return result
            self.logger.error("状态检查解析响应失败")
            return {'online': False, 'error': '解析响应失败'}
        except Exception as e:
            self.logger.error(f"状态检查请求失败: {e}")
            return {'online': False, 'error': f'请求失败: {e}'}

    def parse_user_info(self, data):
        """解析用户信息响应"""
        self.logger.debug(f"解析用户信息响应: {data}")
        if 'error' in data and data['error'] != 'ok':
            self.logger.warning(f"用户信息响应包含错误: {data.get('error', '未知错误')}")
            return {'online': False, 'error': data.get('error', '未知错误')}
        
        status = data.get('status', '')
        status_messages = {
            'E0000': '正常在线',
            'E2606': '需要激活账户',
            'E3001': '流量已用完',
            'E2616': '账户余额不足',
            'E2617': '触发消费保护'
        }
        
        result = {
            'online': status == 'E0000',
            'status': status,
            'status_message': status_messages.get(status, f'未知状态: {status}'),
            'username': data.get('user_name', ''),
            'balance': data.get('user_balance', 0),
            'used_bytes': data.get('sum_bytes', 0),
            'remain_bytes': data.get('remain_bytes', 0),
            'real_name': data.get('real_name', ''),
            'products_name': data.get('products_name', ''),
        }
        
        # 格式化流量显示
        result['used_flow'] = self.format_bytes(result['used_bytes'])
        result['remain_flow'] = self.format_bytes(result['remain_bytes']) if result['remain_bytes'] != -999999 else '无限制'
        
        return result

    def format_bytes(self, bytes_value):
        """格式化字节数为可读格式"""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.2f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.2f} MB"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"

    def get_detailed_status(self):
        """获取详细的在线状态信息"""
        status_info = self.check_online_status()
        
        print("=" * 50)
        print("校园网连接状态")
        print("=" * 50)
        
        if status_info['online']:
            print(f"✅ 状态: {status_info['status_message']}")
            print(f"👤 用户: {status_info['username']} ({status_info['real_name']})")
            print(f"📦 套餐: {status_info['products_name']}")
            print(f"💰 余额: ¥{status_info['balance']:.2f}")
            print(f"📊 已用流量: {status_info['used_flow']}")
            print(f"📈 剩余流量: {status_info['remain_flow']}")
        else:
            print("❌ 状态: 离线")
            if 'error' in status_info:
                print(f"错误信息: {status_info['error']}")
            elif 'status_message' in status_info:
                print(f"原因: {status_info['status_message']}")
        
        print("=" * 50)
        return status_info


def main():
    """主函数 - 示例用法"""
    # 初始化日志系统
    logger = setup_logging()
    logger.info("启动RUC校园网认证程序")
    
    try:
        # 从环境变量读取凭据，或者通过配置文件
        auth = SrunAuth()
    except ValueError as e:
        logger.error(f"凭据配置错误: {e}")
        print("请设置环境变量 SRUN_USERNAME 和 SRUN_PASSWORD，或者创建 config.json 配置文件")
        return
    
    # 获取详细状态
    status_info = auth.get_detailed_status()
    
    if status_info['online']:
        print("当前已在线")
        choice = input("是否要重新认证？(y/n): ")
        if choice.lower() == 'y':
            auth.logout()
            time.sleep(2)
            auth.login()
    else:
        print("当前离线，开始认证...")
        if auth.login():
            # 登录成功后再次显示状态
            print("\n认证完成，最新状态：")
            auth.get_detailed_status()


def keep_alive():
    """保持连接的守护进程"""
    # 初始化日志系统
    logger = setup_logging()
    logger.info("启动RUC校园网保活程序")
    
    try:
        auth = SrunAuth()
    except ValueError as e:
        logger.error(f"凭据配置错误: {e}")
        print("请设置环境变量 SRUN_USERNAME 和 SRUN_PASSWORD")
        return
    
    print("开始保活进程，每5分钟检查一次连接状态...")
    
    while True:
        try:
            status_info = auth.check_online_status()
            
            if not status_info['online']:
                print("检测到掉线，尝试重新认证...")
                print(f"离线原因: {status_info.get('status_message', '未知')}")
                
                if auth.login():
                    print("重新认证成功")
                    auth.get_detailed_status()
                else:
                    print("重新认证失败")
            else:
                print(f"网络连接正常 - {status_info['status_message']}")
                print(f"剩余流量: {status_info['remain_flow']}, 余额: ¥{status_info['balance']:.2f}")
            
            # 等待5分钟
            time.sleep(300)
            
        except KeyboardInterrupt:
            print("程序被用户中断")
            break
        except Exception as e:
            print(f"检查过程中出现错误: {e}")
            time.sleep(60)  # 出错时等待1分钟再重试


def status_only():
    """仅检查状态，不进行认证"""
    # 初始化日志系统
    logger = setup_logging()
    logger.info("启动RUC校园网状态检查程序")
    
    try:
        auth = SrunAuth()
        auth.get_detailed_status()
    except ValueError as e:
        logger.error(f"凭据配置错误: {e}")
        print("请设置环境变量 SRUN_USERNAME 和 SRUN_PASSWORD")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "keep-alive":
            keep_alive()
        elif sys.argv[1] == "status":
            status_only()
        elif sys.argv[1] == "logout":
            logger = setup_logging()
            logger.info("启动RUC校园网注销程序")
            try:
                auth = SrunAuth()
                auth.logout()
            except ValueError as e:
                logger.error(f"凭据配置错误: {e}")
                print("请设置环境变量 SRUN_USERNAME 和 SRUN_PASSWORD")
        else:
            print("使用方法:")
            print("  python srun_auth.py          # 普通认证")
            print("  python srun_auth.py status   # 仅查看状态")
            print("  python srun_auth.py logout   # 注销登录")
            print("  python srun_auth.py keep-alive # 保活模式")
    else:
        main()