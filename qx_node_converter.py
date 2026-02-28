import requests
import yaml
import re
import os
import base64
from urllib.parse import unquote

# ================= 1. 配置区域 =================

# 你的节点订阅链接
SUBSCRIBE_URL = "https://raw.githubusercontent.com/WeiGiegie/vpm/main/lq.snippet"

# 输出给 OpenClash 使用的文件名
OUTPUT_FILE = "Mihomo_Proxies.yaml"

# ================= 2. 下载模块 =================

def fetch_content(url):
    print(f"📥 正在拉取节点订阅: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"❌ 拉取失败: {e}")
        return None

# ================= 3. 核心解析模块 =================

def decode_base64_str(b64_str):
    """安全地解码 Base64 字符串，自动补齐等号"""
    # 替换可能存在的 URL 安全字符
    b64_str = b64_str.replace('-', '+').replace('_', '/')
    # 自动补齐缺失的 = 填充符
    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
    return base64.b64decode(b64_str).decode('utf-8')

def parse_ss_uri(line):
    """
    解析标准的 ss:// URI 格式
    示例: ss://YWVzLTI1...#%E7%BE%8E%E5%9B%BD
    """
    try:
        # 去掉 'ss://' 头部
        content = line[5:]
        
        # 分离 Base64 节点信息 和 URL 编码的节点名字
        parts = content.split('#', 1)
        b64_part = parts[0]
        name_part = parts[1] if len(parts) > 1 else "Unknown_SS_Node"
        
        # 解码节点名字 (把 %E7%BE... 变成中文)
        name = unquote(name_part)
        
        # 解码节点配置 (方法:密码@IP:端口)
        decoded_info = decode_base64_str(b64_part)
        
        if '@' not in decoded_info: return None
        
        user_info, host_info = decoded_info.split('@', 1)
        method, password = user_info.split(':', 1)
        server, port = host_info.split(':', 1)
        
        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password
        }
        return proxy
        
    except Exception as e:
        print(f"  ⚠️ 解析某条 ss:// 链接时出错, 已跳过: {e}")
        return None

def parse_qx_shadowsocks(line):
    """解析圈X私有 SS 语法 (保留该功能以备不时之需)"""
    line = re.sub(r'^shadowsocks\s*=\s*', '', line, flags=re.IGNORECASE)
    parts = [p.strip() for p in line.split(',')]
    if not parts: return None

    server_port = parts[0].split(':')
    if len(server_port) != 2: return None

    proxy = {
        "type": "ss",
        "server": server_port[0],
        "port": int(server_port[1]),
    }

    params = {}
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1)
            params[k.strip().lower()] = v.strip()

    proxy['name'] = params.get('tag', f"SS_{server_port[0]}")
    if 'method' in params: proxy['cipher'] = params['method']
    if 'password' in params: proxy['password'] = params['password']
    if 'udp-relay' in params: proxy['udp'] = params['udp-relay'].lower() == 'true'

    if 'obfs' in params:
        proxy['plugin'] = 'obfs'
        proxy['plugin-opts'] = {'mode': params['obfs']}
        if 'obfs-host' in params: proxy['plugin-opts']['host'] = params['obfs-host']

    return proxy

# ================= 4. 主流程 =================

def main():
    content = fetch_content(SUBSCRIBE_URL)
    if not content:
        print("⚠️ 无法获取节点内容，脚本退出。")
        return

    proxies_list = []
    print("⏳ 正在进行跨平台格式翻译与 Base64 解码...")
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')): continue
            
        # 1. 命中标准 ss:// 链接 (你提供的格式)
        if line.lower().startswith('ss://'):
            node = parse_ss_uri(line)
            if node: proxies_list.append(node)
            
        # 2. 命中圈X专属 shadowsocks=
        elif line.lower().startswith('shadowsocks='):
            node = parse_qx_shadowsocks(line)
            if node: proxies_list.append(node)

    if not proxies_list:
        print("⚠️ 未能解析出任何有效节点！")
        return

    # 构建 Mihomo (OpenClash) 标准 YAML
    clash_provider = {"proxies": proxies_list}

    print(f"✅ 解析成功！共“抢救”出 {len(proxies_list)} 个可用节点。")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_provider, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
    print(f"💾 转换完成！已保存为标准 YAML 订阅文件: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
