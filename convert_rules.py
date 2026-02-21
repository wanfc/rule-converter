import requests
import os
import re
import ipaddress
import hashlib # 用于计算MD5，实现增量更新
import yaml # 记得在 Actions 里执行 pip install pyyaml

# ================= 1. 配置区域 =================

# 定义三个顶层目录，对应不同的软件需求
DIR_QX = "QuantumultX"     # QX 专用：HOST 格式
DIR_CLASSICAL = "Classical" # 经典版：DOMAIN-SUFFIX 格式 (含 no-resolve)
DIR_MIHOMO = "Mihomo"       # Mihomo 专用：符合 behavior: domain/ipcidr 的 text 格式
ERROR_LOG_FILE = "error.txt"

def load_sources():
    """从外部 YAML 文件加载源列表"""
    path = os.path.join("SourceList", "sources.yaml")
    if not os.path.exists(path):
        print(f"❌ 找不到配置文件: {path}")
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) 
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
    print(f"  📥 正在拉取: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"  ❌ 拉取失败: {e}")
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
    无论源文件是 +.mask.me 还是 DOMAIN-SUFFIX,mask.me，
    这里统统会变成 ('domain-suffix', 'mask.me')。
    """
    content = content.strip()
    if not content: return None, None

    # 过滤掉白名单规则 (@@) 和 AdGuard 的高级正则
    if content.startswith('@@') or '##' in content or '#@#' in content: return None, None
    
    # 处理 AdGuard 风格 (||example.com^)
    if content.startswith('||'): content = content[2:].split('^')[0]
    # 处理 SmartDNS/Dnsmasq 风格
    elif content.startswith('address') and '/' in content:
        parts = content.split('/')
        if len(parts) >= 2: content = parts[1].strip()

    # 处理标准前缀格式
    if ',' in content:
        parts = content.split(',', 1)
        prefix = parts[0].strip().upper()
        # 提取第一个逗号后的值，并剥离掉末尾的策略组或 no-resolve
        value = parts[1].split(',', 1)[0].strip()
        value = re.sub(r'\s*no-resolve', '', value, flags=re.IGNORECASE).strip()
        
        if 'IP' in prefix and '6' in prefix and 'CIDR' in prefix: return 'ipv6', value
        if 'IP' in prefix and 'CIDR' in prefix: return 'ipv4', value 
        if 'SUFFIX' in prefix: return 'domain-suffix', value
        if 'DOMAIN' in prefix or 'HOST' in prefix: return 'domain', value
        return None, None # 其他关键字一律丢弃

    # 处理纯文本 IP
    try:
        net = ipaddress.ip_network(content, strict=False)
        return ('ipv4' if net.version == 4 else 'ipv6'), str(net)
    except ValueError: pass

    # 拦截包含正则符的行
    if any(char in content for char in ['/', '*', '=', '|', ':', '(', ')']): return None, None
    
    # 识别 Meta/Surge 的通配符风格 (+. 统一转为 domain-suffix)
    if content.startswith('+.'): return 'domain-suffix', content[2:]
    if content.startswith('.'): return 'domain-suffix', content[1:]
    
    # 纯域名识别逻辑
    if ' ' not in content and '.' in content:
        return ('domain' if strict_mode else 'domain-suffix'), content
        
    return None, None

def process_rules(contents_list, target_type, policy_name, strict_mode):
    """
    接收多个文件内容的列表（按 YAML 中的书写顺序排列）。
    执行多源合并与智能去重。
    """
    qx = []
    classical = []
    mihomo_text = []

    # 核心字典：记录 纯值(如 mask.me) -> 类型(如 domain)
    # Python 3.7+ 的字典是有序的，会严格保留插入顺序
    unique_rules = {}

    # 第一轮：遍历所有文本，执行合并与优先级判定
    for content in contents_list:
        for line in content.splitlines():
            line = clean_line(line)
            if not line or line.lower().startswith(('payload:', 'version:', 'address', '#')): continue

            dtype, val = smart_detect(line, strict_mode)
            if not dtype: continue

            # 过滤类型不匹配的规则
            if target_type == 'domain' and dtype in ['ipv4', 'ipv6']: continue
            if target_type == 'ip' and dtype in ['domain', 'domain-suffix']: continue

            # 💡 核心位置：智能去重与位置控制
            if val not in unique_rules:
                # 第一次遇到这个域名/IP，直接按它的顺序记录类型
                unique_rules[val] = dtype
            else:
                existing_dtype = unique_rules[val]
                
                # 情景 1：旧的(URL1)是精确匹配(DOMAIN)，新的(URL2)是后缀匹配(DOMAIN-SUFFIX)
                if existing_dtype == 'domain' and dtype == 'domain-suffix':
                    # 【关键动作】：通过 del 删除旧键，将其从 URL1 的靠前位置移除
                    del unique_rules[val]
                    # 然后重新赋值，它就会自动排到当前字典的最后面（即 URL2 所在的靠后位置）
                    # 这样完美保护了 URL1 里的二级/三级域名的自上而下匹配优先级
                    unique_rules[val] = 'domain-suffix'
                
                # 情景 2：旧的(URL1)是后缀匹配(DOMAIN-SUFFIX)，新的(URL2)是精确匹配(DOMAIN)
                # 后来的范围更小，没有必要保留，直接什么都不做（忽略 URL2 的规则）
                
                # 情景 3：完全重复（都是 DOMAIN 或 都是 DOMAIN-SUFFIX）
                # 同样什么都不做，保留它第一次出现的位置

    # 第二轮：按照处理完毕的有序字典，生成最终要写入的三种列表
    for val, dtype in unique_rules.items():
        if dtype == 'ipv4':
            qx.append(f"IP-CIDR, {val}, {policy_name}")
            classical.append(f"IP-CIDR,{val},no-resolve")
            mihomo_text.append(val)
        elif dtype == 'ipv6':
            qx.append(f"IP6-CIDR, {val}, {policy_name}")
            classical.append(f"IP-CIDR6,{val},no-resolve")
            mihomo_text.append(val)
        elif dtype == 'domain-suffix':
            qx.append(f"HOST-SUFFIX, {val}, {policy_name}")
            classical.append(f"DOMAIN-SUFFIX,{val}")
            mihomo_text.append(f"+.{val}")
        elif dtype == 'domain':
            qx.append(f"HOST, {val}, {policy_name}")
            classical.append(f"DOMAIN,{val}")
            mihomo_text.append(val)

    return {"qx": qx, "classical": classical, "mihomo": mihomo_text}

# ================= 4. 文件保存与主流程 =================

def save_text(path, lines):
    """保存逻辑：包含 MD5 校验，避免不必要的硬盘读写与 Git 提交"""
    if not lines: return
    new_content = '\n'.join(lines)
    
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            if calculate_md5(new_content) == calculate_md5(f.read()):
                print(f"  ⚠️ 内容无变化，跳过更新: {os.path.basename(path)}")
                return
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"  💾 文件已更新: {path} (精简去重后共 {len(lines)} 条)")

def main():
    create_dirs()
    clean_old_error_log()

    source_list = load_sources()
    if not source_list:
        print("⚠️ 任务列表为空或加载失败，脚本退出。")
        return

    print(f"🚀 脚本启动：共加载 {len(source_list)} 个任务...")
    
    failed_urls = []

    for item in source_list:
        # 兼容处理：YAML 中 url 可能是单个字符串，也可能是列表
        urls = item['url']
        if isinstance(urls, str):
            urls = [urls]
            
        name, policy, rtype = item['name'], item['policy'], item['type']
        is_strict = item.get('strict', False)
        
        print(f"\n[任务] {name} | 类型: {rtype} | 包含 {len(urls)} 个源地址")
        
        combined_contents = []
        task_failed = False
        
        # 严格按照 YAML 中的先后顺序下载并拼接
        for u in urls:
            content = fetch_content(u)
            if not content:
                failed_urls.append(u)
                task_failed = True
                break # 任何一个源失败，该合并任务立刻中止（容灾机制）
            combined_contents.append(content)
            
        if task_failed:
            print(f"  ⚠️ 警告：因为部分源下载失败，为防破坏旧文件，跳过该任务！")
            continue 
        
        # 传入文本列表进行智能去重合并
        res = process_rules(combined_contents, rtype, policy, is_strict)
        sub = "IP" if rtype == 'ip' else "Domain"

        # 写入三个分支目录（即使有 3 个 URL，最终也会合并成这 1 个文件）
        save_text(os.path.join(DIR_QX, sub, f"{name}.list"), res['qx'])
        save_text(os.path.join(DIR_CLASSICAL, sub, f"{name}.list"), res['classical'])
        save_text(os.path.join(DIR_MIHOMO, sub, f"{name}.list"), res['mihomo'])

    # 错误处理与日志报告
    if failed_urls:
        with open(ERROR_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("下载失败的源地址：\n" + '\n'.join(failed_urls))
        print(f"\n⚠️ 脚本结束，有 {len(failed_urls)} 个源失败，详情请看 error.txt")
    else:
        print("\n🎉 所有任务处理圆满完成！")

if __name__ == "__main__":
    main()