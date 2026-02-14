import requests
import os
import re
import ipaddress
import hashlib  # 用于计算MD5，实现增量更新
import yaml # 记得在 Actions 里执行 pip install pyyaml

# ================= 配置区域 =================

# 定义三个顶层目录，对应不同的软件需求
DIR_QX = "QuantumultX"     # QX 专用：HOST 格式
DIR_CLASSICAL = "Classical" # 经典版：DOMAIN-SUFFIX 格式 (含 no-resolve)
DIR_MIHOMO = "Mihomo"       # Mihomo 专用：符合 behavior: domain/ipcidr 的 text 格式
ERROR_LOG_FILE = "error.txt"

def load_sources():
    path = os.path.join("SourceList", "sources.yaml")
    if not os.path.exists(path):
        print(f"❌ 找不到配置文件: {path}")
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) # 核心改动
    except Exception as e:
        print(f"❌ 读取配置文件出错: {e}")
        return []

# ================= 2. 基础工具函数 =================

def create_dirs():
    """创建三级文件夹结构，确保分类存放"""
    paths = [
        os.path.join(DIR_QX, "IP"), os.path.join(DIR_QX, "Domain"),
        os.path.join(DIR_CLASSICAL, "IP"), os.path.join(DIR_CLASSICAL, "Domain"),
        os.path.join(DIR_MIHOMO, "IP"), os.path.join(DIR_MIHOMO, "Domain")
    ]
    for p in paths:
        if not os.path.exists(p):
            os.makedirs(p)

def clean_old_error_log():
    """运行前重置错误日志，防止旧错误干扰"""
    if os.path.exists(ERROR_LOG_FILE):
        try: os.remove(ERROR_LOG_FILE)
        except: pass

def calculate_md5(text):
    """用于实现增量更新：只在内容变化时写入硬盘"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def fetch_content(url):
    """通用的下载函数，带超时和简单的请求头"""
    print(f"📥 正在下载: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        return None

def clean_line(line):
    """
    初步清洗：
    1. 删注释 (#, //)
    2. 删 AdGuard 的拦截符 (!)
    3. 删 YAML 列表符 (- )
    4. 删前后引号
    """
    line = re.split(r'#|//', line)[0]
    if line.strip().startswith('!'): return ''
    line = line.strip()
    if line.startswith('- '): line = line[1:].strip()
    return line.strip("'").strip('"')

# ================= 3. 核心转换逻辑 =================

def smart_detect(content, strict_mode=False):
    """
    智能识别引擎：将各种乱糟糟的原始规则“脱水”，只提取纯净的 IP 或 域名。
    
    参数：
      strict_mode: 是否开启严格模式。
        - True: 纯域名视为精确匹配 (DOMAIN)
        - False: 纯域名视为后缀匹配 (DOMAIN-SUFFIX) - 推荐用于去广告
    
    返回：
      (类型, 纯净值) 或者 (None, None)
    """
    content = content.strip()
    if not content: return None, None

    # 过滤掉白名单规则 (@@) 和 AdGuard 的高级正则，因为分流 Provider 不支持
    if content.startswith('@@') or '##' in content or '#@#' in content: return None, None
    
    # 处理 AdGuard 风格 (||example.com^)
    if content.startswith('||'): content = content[2:].split('^')[0]
    # 处理 SmartDNS/Dnsmasq 风格
    elif content.startswith('address') and '/' in content:
        parts = content.split('/')
        if len(parts) >= 2: content = parts[1].strip()

    # 处理标准前缀格式 (如 DOMAIN-SUFFIX,google.com,Proxy)
    if ',' in content:
        parts = content.split(',', 1)
        prefix = parts[0].strip().upper()
        # 提取第一个逗号后的值，并剥离掉末尾的策略组或 no-resolve
        value = parts[1].split(',', 1)[0].strip()
        value = re.sub(r'\s*no-resolve', '', value, flags=re.IGNORECASE).strip()
        
        # 映射识别到的类型
        # 兼容 QX 的 IP6-CIDR 和 Clash 的 IP-CIDR6
        if 'IP' in prefix and '6' in prefix and 'CIDR' in prefix: return 'ipv6', value
        # 兼容标准 IP-CIDR
        if 'IP' in prefix and 'CIDR' in prefix: return 'ipv4', value 
        # 兼容 HOST-SUFFIX / DOMAIN-SUFFIX
        if 'SUFFIX' in prefix: return 'domain-suffix', value
        # 兼容 HOST / DOMAIN
        if 'DOMAIN' in prefix or 'HOST' in prefix: return 'domain', value
        return None, None # 其他关键字 (如 USER-AGENT) 一律丢弃

    # 处理纯文本 IP (如 1.1.1.1)
    try:
        net = ipaddress.ip_network(content, strict=False)
        return ('ipv4' if net.version == 4 else 'ipv6'), str(net)
    except ValueError: pass

    # 处理纯文本域名
    # 拦截包含正则符的行，保证 Provider 兼容性
    if any(char in content for char in ['/', '*', '=', '|', ':', '(', ')']): return None, None
    
    # 识别 Meta/Surge 的通配符风格 (+.google.com 或 .google.com)
    if content.startswith('+.'): return 'domain-suffix', content[2:]
    if content.startswith('.'): return 'domain-suffix', content[1:]
    
    # 纯域名识别逻辑：如果不带点则视为无效
    if ' ' not in content and '.' in content:
        return ('domain' if strict_mode else 'domain-suffix'), content
        
    return None, None

def process_rules(content, target_type, policy_name, strict_mode):
    """
    根据识别出的类型，将规则分发到三个不同的输出队列中
    """
    qx = []
    classical = []
    mihomo_text = []

    for line in content.splitlines():
        line = clean_line(line)
        if not line or line.lower().startswith(('payload:', 'version:', 'address', '#')): continue

        dtype, val = smart_detect(line, strict_mode)
        if not dtype: continue

        # 确保 Domain 文件不混入 IP，IP 文件不混入 Domain
        if target_type == 'domain' and dtype in ['ipv4', 'ipv6']: continue
        if target_type == 'ip' and dtype in ['domain', 'domain-suffix']: continue

        # --- 格式化输出逻辑 ---

        if dtype == 'ipv4':
            # QX: 标准格式，无 no-resolve
            qx.append(f"IP-CIDR, {val}, {policy_name}")
            # Classical: 带参数，无抬头
            classical.append(f"IP-CIDR,{val},no-resolve")
            # Mihomo: 纯净文本 (format: text)
            mihomo_text.append(val)
            
        elif dtype == 'ipv6':
            qx.append(f"IP6-CIDR, {val}, {policy_name}")
            classical.append(f"IP-CIDR6,{val},no-resolve")
            mihomo_text.append(val)
            
        elif dtype == 'domain-suffix':
            qx.append(f"HOST-SUFFIX, {val}, {policy_name}")
            classical.append(f"DOMAIN-SUFFIX,{val}")
            # Mihomo: 使用 +. 通配符代表后缀匹配
            mihomo_text.append(f"+.{val}")
            
        elif dtype == 'domain':
            qx.append(f"HOST, {val}, {policy_name}")
            classical.append(f"DOMAIN,{val}")
            # Mihomo: 不带前缀代表精确匹配
            mihomo_text.append(val)

    return {"qx": qx, "classical": classical, "mihomo": mihomo_text}

# ================= 4. 文件保存与主流程 =================

def save_text(path, lines):
    """保存逻辑：包含 MD5 校验，避免不必要的 Git Commit"""
    if not lines: return
    new_content = '\n'.join(lines)
    
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            if calculate_md5(new_content) == calculate_md5(f.read()):
                print(f"  ⚠️ 内容无变化，跳过: {os.path.basename(path)}")
                return
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"  💾 文件已更新: {path} (总计 {len(lines)} 行)")

def main():
    # 初始化环境
    create_dirs()
    clean_old_error_log()

    # 核心变化：从外部加载源
    source_list = load_sources()
    if not source_list:
        print("⚠️ 任务列表为空，脚本退出。")
        return

    print(f"🚀 脚本启动：共加载 {len(source_list)} 个任务...")
    
    failed_urls = []

    # 核心循环
    for item in source_list:
        url, name, policy, rtype = item['url'], item['name'], item['policy'], item['type']
        is_strict = item.get('strict', False)
        
        print(f"\n[任务] {name} | 类型: {rtype}")
        
        content = fetch_content(url)
        if not content:
            failed_urls.append(url)
            continue 
        
        # 获取三种格式的转换结果
        res = process_rules(content, rtype, policy, is_strict)
        sub = "IP" if rtype == 'ip' else "Domain"

        # 1. 写入 QuantumultX (单文件)
        save_text(os.path.join(DIR_QX, sub, f"{name}.list"), res['qx'])

        # 2. 写入 Classical (单文件，IP 内置 no-resolve)
        save_text(os.path.join(DIR_CLASSICAL, sub, f"{name}.list"), res['classical'])

        # 3. 写入 Mihomo (单文件，通配符风格)
        save_text(os.path.join(DIR_MIHOMO, sub, f"{name}.list"), res['mihomo'])

    # 错误处理
    if failed_urls:
        with open(ERROR_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("下载失败清单：\n" + '\n'.join(failed_urls))
        print(f"\n⚠️ 脚本结束，但有 {len(failed_urls)} 个源失败，请检查 error.txt")
    else:
        print("\n🎉 转换全部圆满完成！")

if __name__ == "__main__":

    main()
