import requests
import yaml
import re
import os

# ================= 1. 配置区域 =================

# 你的圈X节点订阅链接 (可随时更换)
SUBSCRIBE_URL = "https://raw.githubusercontent.com/WeiGiegie/vpm/main/lq.snippet"

# 输出给 OpenClash 使用的文件名
OUTPUT_FILE = "Mihomo_Proxies.yaml"

# ================= 2. 下载模块 =================

def fetch_content(url):
    """拉取订阅链接内容"""
    print(f"📥 正在拉取节点订阅: {url}")
    try:
        # 伪装成 Quantumult X 的请求头，防止部分机场或源阻断屏蔽
        headers = {'User-Agent': 'Quantumult X/1.0.30 (iPhone14,2; iOS 16.5)'}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"❌ 拉取失败: {e}")
        return None

# ================= 3. 核心解析模块 =================

def parse_qx_shadowsocks(line):
    """
    解析圈X的 Shadowsocks 节点语法
    示例: shadowsocks=1.1.1.1:443, method=chacha20, password=pwd, obfs=tls, obfs-host=bing.com, tag=Node1
    """
    # 剔除开头的 shadowsocks= (忽略大小写和空格)
    line = re.sub(r'^shadowsocks\s*=\s*', '', line, flags=re.IGNORECASE)
    parts = [p.strip() for p in line.split(',')]
    if not parts: return None

    # 第一段永远是 IP:端口
    server_port = parts[0].split(':')
    if len(server_port) != 2: return None

    # 构建 Mihomo 支持的基础字典
    proxy = {
        "type": "ss",
        "server": server_port[0],
        "port": int(server_port[1]),
    }

    # 解析后续的键值对参数
    params = {}
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1)
            params[k.strip().lower()] = v.strip()

    # --- 字段映射字典 (圈X -> Mihomo) ---
    proxy['name'] = params.get('tag', f"SS_{server_port[0]}")
    if 'method' in params: proxy['cipher'] = params['method']
    if 'password' in params: proxy['password'] = params['password']
    
    # 圈X udp-relay=true -> Mihomo udp: true
    if 'udp-relay' in params: 
        proxy['udp'] = params['udp-relay'].lower() == 'true'

    # --- 处理 obfs 混淆插件 ---
    if 'obfs' in params:
        proxy['plugin'] = 'obfs'
        proxy['plugin-opts'] = {'mode': params['obfs']}
        # 混淆域名
        if 'obfs-host' in params:
            proxy['plugin-opts']['host'] = params['obfs-host']

    return proxy


def parse_qx_trojan(line):
    """
    解析圈X的 Trojan 节点语法 (额外赠送的防漏解析)
    示例: trojan=1.1.1.1:443, password=pwd, over-tls=true, tls-host=bing.com, tag=Node2
    """
    line = re.sub(r'^trojan\s*=\s*', '', line, flags=re.IGNORECASE)
    parts = [p.strip() for p in line.split(',')]
    if not parts: return None

    server_port = parts[0].split(':')
    if len(server_port) != 2: return None

    proxy = {
        "type": "trojan",
        "server": server_port[0],
        "port": int(server_port[1]),
    }

    params = {}
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1)
            params[k.strip().lower()] = v.strip()

    proxy['name'] = params.get('tag', f"Trojan_{server_port[0]}")
    if 'password' in params: proxy['password'] = params['password']
    
    # SNI (服务器名称指示)
    if 'tls-host' in params: proxy['sni'] = params['tls-host']
    elif 'sni' in params: proxy['sni'] = params['sni']
    
    # 跳过证书验证
    if 'tls-verification' in params:
        proxy['skip-cert-verify'] = params['tls-verification'].lower() == 'false'

    return proxy

# ================= 4. 主流程 =================

def main():
    content = fetch_content(SUBSCRIBE_URL)
    if not content:
        print("⚠️ 无法获取节点内容，脚本退出。")
        return

    proxies_list = []
    
    print("⏳ 正在进行跨平台格式翻译...")
    
    # 逐行遍历并解析
    for line in content.splitlines():
        line = line.strip()
        # 跳过空行和注释
        if not line or line.startswith(('#', ';', '//')): 
            continue
            
        # 1. 命中 Shadowsocks 节点
        if line.lower().startswith('shadowsocks'):
            node = parse_qx_shadowsocks(line)
            if node: proxies_list.append(node)
                
        # 2. 命中 Trojan 节点
        elif line.lower().startswith('trojan'):
            node = parse_qx_trojan(line)
            if node: proxies_list.append(node)

    if not proxies_list:
        print("⚠️ 未能解析出任何有效节点！可能是源链接失效或格式不匹配。")
        return

    # 构建 Mihomo (OpenClash) Provider 必须的标准包裹格式
    clash_provider = {
        "proxies": proxies_list
    }

    print(f"✅ 解析成功！共“抢救”出 {len(proxies_list)} 个可用节点。")
    
    # 写入 YAML 文件
    # allow_unicode=True 确保节点名字里的中文不会变成乱码 (\u4e2d...)
    # sort_keys=False 保持我们构建字典时的属性顺序 (好看且规范)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_provider, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
    print(f"💾 转换完成！已保存为标准 YAML 订阅文件: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
