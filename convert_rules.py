import requests
import os
import re
import ipaddress
import hashlib # 用于计算 MD5，实现增量更新
import yaml # 记得在 Actions 里执行 pip install pyyaml
from collections import OrderedDict
import subprocess # 用于调用外部 Mihomo 编译器
import concurrent.futures # 引入并发线程池模块，开启多核狂飙模式

# ================= 1. 全局架构配置区 =================

# 定义四个顶层目录，对应不同代理软件的物理分发需求
DIR_QX = "QuantumultX"      # QX 专用：HOST 格式
DIR_CLASSICAL = "Classical" # 经典版：DOMAIN-SUFFIX 格式 (带 no-resolve 防漏)
DIR_MIHOMO = "Mihomo"       # Mihomo 纯净版：行为驱动的 payload 极简文本格式
DIR_MRS = "MRS"             # MRS 终极版：Mihomo 底层二进制预编译格式
ERROR_LOG_FILE = "error.txt"

def load_sources():
    """从外部 YAML 文件加载订阅源与清洗规则 (含黑名单 exclude)"""
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

# ================= 2. 基础物理设施与工具 =================

def create_dirs():
    """初始化三级文件夹结构，确保兵马未动粮草先行"""
    paths = [
        os.path.join(DIR_QX, "IP"), os.path.join(DIR_QX, "Domain"),
        os.path.join(DIR_CLASSICAL, "IP"), os.path.join(DIR_CLASSICAL, "Domain"),
        os.path.join(DIR_MIHOMO, "IP"), os.path.join(DIR_MIHOMO, "Domain"),
        os.path.join(DIR_MRS, "IP"), os.path.join(DIR_MRS, "Domain")
    ]
    for p in paths:
        if not os.path.exists(p):
            os.makedirs(p)

def clean_old_error_log():
    """运行前重置错误日志，防止旧报错干扰本次任务判断"""
    if os.path.exists(ERROR_LOG_FILE):
        try: os.remove(ERROR_LOG_FILE)
        except: pass

def calculate_md5(text):
    """计算文本指纹：用于实现增量更新，只在内容真变化时才写入硬盘，拯救 SSD 寿命"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def fetch_content(url, logs):
    """带超时保护与反爬伪装的网络下载器"""
    logs.append(f"  📥 [下载中] {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        logs.append(f"  ❌ [下载失败] {url} -> {e}")
        return None

def clean_line(line):
    """
    第一道防线：清洗脏数据
    1. 删注释 (#, //)  <- 防止规则尾部带说明导致解析崩溃
    2. 删 AdGuard 的白名单拦截符 (!)
    3. 删 YAML 列表符 (- )
    4. 删无用的前后引号
    """
    line = re.split(r'#|//', line)[0]
    if line.strip().startswith('!'): return ''
    line = line.strip()
    if line.startswith('- '): line = line[1:].strip()
    return line.strip("'").strip('"')

def smart_detect(content, strict_mode=False):
    """
    核心降维引擎：将全世界五花八门的规则格式“脱水”，榨取最纯净的物理特征。
    无论它是 +.mask.me 还是 DOMAIN-SUFFIX,mask.me，最后统统归一化！
    """
    content = content.strip()
    if not content: return None, None

    # 过滤掉白名单规则 (@@) 和 AdGuard 的高级正则
    if content.startswith('@@') or '##' in content or '#@#' in content: return None, None
    
    # 剥离 AdGuard 风格尾巴 (||example.com^)
    if content.startswith('||'): content = content[2:].split('^')[0]
    # 剥离 SmartDNS/Dnsmasq 风格
    elif content.startswith('address') and '/' in content:
        parts = content.split('/')
        if len(parts) >= 2: content = parts[1].strip()

    # 处理传统标准前缀格式 (如 DOMAIN, IP-CIDR, IP-ASN)
    if ',' in content:
        parts = content.split(',', 1)
        prefix = parts[0].strip().upper()
        # 提取值，并残酷剥离末尾的策略组动作或 no-resolve 参数，实现动作解耦
        value = parts[1].split(',', 1)[0].strip()
        value = re.sub(r'\s*no-resolve', '', value, flags=re.IGNORECASE).strip()
        
        # 精准类型判定
        if 'IP-ASN' in prefix: return 'ip-asn', value
        if 'IP' in prefix and '6' in prefix and 'CIDR' in prefix: return 'ipv6', value
        if 'IP' in prefix and 'CIDR' in prefix: return 'ipv4', value 
        if 'SUFFIX' in prefix: return 'domain-suffix', value
        if 'DOMAIN' in prefix or 'HOST' in prefix: return 'domain', value
        return None, None # 未知协议，当场抛弃

    # 暴力猜测：尝试解析为 IP 地址/掩码
    try:
        net = ipaddress.ip_network(content, strict=False)
        return ('ipv4' if net.version == 4 else 'ipv6'), str(net)
    except ValueError: pass

    # 拦截包含特殊正则符的高危脏行 (透明代理底层无法处理复杂正则)
    if any(char in content for char in ['/', '*', '=', '|', ':', '(', ')']): return None, None    
    
    # 剥离 Meta/Surge 的通配符风格 (+. 统一转为 domain-suffix)
    if content.startswith('+.'): return 'domain-suffix', content[2:]
    if content.startswith('.'): return 'domain-suffix', content[1:]    
    
    # 纯域名降维判断：开启严格模式就是精确匹配，否则默认连坐后缀匹配
    if ' ' not in content and '.' in content:
        return ('domain' if strict_mode else 'domain-suffix'), content
        
    return None, None

# ================= 3. 高级规则融合与黑名单绞杀引擎 =================

def process_rules(contents_list, target_type, policy_name, strict_mode, excludes=None):
    """
    主炮火控系统：处理多源合并、严格去重，并引入【四维黑名单绞杀引擎】
    """
    qx = []
    classical = []
    mihomo_text = []
    # 使用 OrderedDict 无视环境差异，100% 锁定规则读取和输出的物理顺序
    unique_rules = OrderedDict()

    # ---------------- 💡 预编译黑名单特征库 (算力优化) ----------------
    # 在循环外将文本字符串转化为网络对象，避免在几十万行循环中重复算力浪费
    ex_domains = set()
    ex_asns = set()
    ex_nets_v4 = []
    ex_nets_v6 = []

    if excludes:
        for ex in excludes:
            # 妙招：用自己的 smart_detect 把 YAML 里的排除规则也脱水
            e_type, e_val = smart_detect(str(ex), strict_mode)
            val_to_use = e_val if e_val else str(ex).strip()
            
            # 分门别类建库，IP 段直接转化成底层的 ip_network 对象，准备执行掩码包含计算
            if e_type == 'ipv4':
                try: ex_nets_v4.append(ipaddress.ip_network(val_to_use, strict=False))
                except: pass
            elif e_type == 'ipv6':
                try: ex_nets_v6.append(ipaddress.ip_network(val_to_use, strict=False))
                except: pass
            elif e_type == 'ip-asn':
                ex_asns.add(val_to_use)
            else:
                ex_domains.add(val_to_use)
    # ----------------------------------------------------------------

    for content in contents_list:
        for line in content.splitlines():
            line = clean_line(line)
            if not line or line.lower().startswith(('payload:', 'version:', 'address', '#')): continue

            dtype, val = smart_detect(line, strict_mode)
            if not dtype: continue

            # 防呆边界防御：防止 IP-ASN 混入 Domain 列表导致 Mihomo 崩溃
            if target_type == 'domain' and dtype in ['ipv4', 'ipv6', 'ip-asn']: continue
            if target_type == 'ip' and dtype in ['domain', 'domain-suffix']: continue

            # ---------------- 💡 执行四维黑名单绞杀 ----------------
            is_excluded = False
            
            # 1. 域名绞杀：精准命中，或触发子域名连坐 (如 exclude qq.com, 杀掉 api.qq.com)
            if dtype in ['domain', 'domain-suffix']:
                if val in ex_domains:
                    is_excluded = True
                else:
                    for ex_d in ex_domains:
                        if val.endswith('.' + ex_d): # 加 . 防止 aqq.com 被误杀
                            is_excluded = True
                            break
                            
            # 2. IPv4 降维绞杀：子网掩码包含计算 (目标 1.1.1.1/32 被包含在 1.0.0.0/8 中，当场击毙)
            elif dtype == 'ipv4':
                try:
                    target_net = ipaddress.ip_network(val, strict=False)
                    for ex_net in ex_nets_v4:
                        if target_net.subnet_of(ex_net): 
                            is_excluded = True
                            break
                except: pass
                
            # 3. IPv6 降维绞杀
            elif dtype == 'ipv6':
                try:
                    target_net = ipaddress.ip_network(val, strict=False)
                    for ex_net in ex_nets_v6:
                        if target_net.subnet_of(ex_net):
                            is_excluded = True
                            break
                except: pass
                
            # 4. ASN 精准绞杀
            elif dtype == 'ip-asn':
                if val in ex_asns:
                    is_excluded = True

            if is_excluded:
                continue # 命中黑名单，物理粉碎，绝对不进入最终名单！
            # ----------------------------------------------------------------

            # 智能去重与作用域升级逻辑
            if val not in unique_rules:
                unique_rules[val] = dtype
            else:
                existing_dtype = unique_rules[val]
                # 如果旧的是精确匹配，新的是后缀匹配，删除旧的，在尾部重新插入，防止覆盖二三级域名优先级
                if existing_dtype == 'domain' and dtype == 'domain-suffix':
                    del unique_rules[val]
                    unique_rules[val] = 'domain-suffix'

    # 第二轮清洗：严格按照锁定的顺序，格式化输出到各大平台的兼容数组中
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
        elif dtype == 'ip-asn':
            qx.append(f"IP-ASN, {val}, {policy_name}")
            classical.append(f"IP-ASN,{val},no-resolve")
            mihomo_text.append(f"IP-ASN,{val}")

    return {"qx": qx, "classical": classical, "mihomo": mihomo_text}

# ================= 4. 硬盘写入与二进制编译 =================

def save_text(path, lines, logs):
    """带增量校验的硬盘写入：文件没有实质变更就不去触碰硬盘"""
    if not lines: return False
    new_content = '\n'.join(lines)
    
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            if calculate_md5(new_content) == calculate_md5(f.read()):
                logs.append(f"  ⏭️ [跳过更新] 内容无变化: {os.path.basename(path)}")
                return False 
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    logs.append(f"  💾 [保存成功] {os.path.basename(path)} (去重清洗后共 {len(lines)} 条)")
    return True # 返回 True 告诉主控程序：这文件我改了！

def compile_to_mrs(txt_path, mrs_path, rule_type, logs):
    """召唤 Mihomo 核心，将极简 payload 文本降维打击成二进制 .mrs 源文件"""
    logs.append(f"  ⚙️ [编译 MRS] 正在处理: {os.path.basename(mrs_path)}")
    try:
        cmd = ["mihomo", "convert-ruleset", rule_type, "text", txt_path, mrs_path]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logs.append(f"  ✅ [编译完成] {os.path.basename(mrs_path)}")
    except subprocess.CalledProcessError as e:
        logs.append(f"  ❌ [编译失败] {os.path.basename(txt_path)}")
        # 拦截 Mihomo 的底层 Go 语言报错：如果是因全规则集都是 ASN 导致的空数组，静默放过
        if "empty rule" in e.stderr:
            logs.append("     ⚠️ [中断] 规则集不支持编译 (全为 ASN)，已保留文本格式，跳过二进制。")
        else:
            logs.append(f"     详细错误: {e.stderr.strip().splitlines()[0]}")

# ================= 5. 并发任务执行单元 =================

def process_single_task(item):
    """
    独立单兵作战单元 (完美支持多核并发)
    一切日志在这里被原子化收集，彻底杜绝多线程时打印内容相互插队！
    """
    logs = [] # 单任务专属防插队记事本    
    urls = item['url']
    if isinstance(urls, str): urls = [urls]
        
    name, policy, rtype = item['name'], item['policy'], item['type']
    is_strict = item.get('strict', False)
    
    # 提取黑名单 (支持找不到时安全返回空列表)
    excludes = item.get('exclude', []) 
    
    logs.append(f"\n🚀 [启动任务] {name} | 类型: {rtype} | 源地址: {len(urls)} 个 | 黑名单: {len(excludes)} 项")
    
    combined_contents = []
    task_failed_urls = []
    
    # 强制按 YAML 顺位下载，锁定规则优先级
    for u in urls:
        content = fetch_content(u, logs)
        if not content:
            task_failed_urls.append(u)
            break 
        combined_contents.append(content)
        
    if task_failed_urls:
        logs.append(f"  ⚠️ [任务中止] {name} 部分上游源失效，停止合成！")
        return task_failed_urls, '\n'.join(logs)
    
    # 将下载的脏数据和清洗要求，移交中央主炮火控系统 (process_rules)
    res = process_rules(combined_contents, rtype, policy, is_strict, excludes)
    sub = "IP" if rtype == 'ip' else "Domain"

    # 将清洗完毕的三军数据，分别写入三大基地
    save_text(os.path.join(DIR_QX, sub, f"{name}.list"), res['qx'], logs)
    save_text(os.path.join(DIR_CLASSICAL, sub, f"{name}.list"), res['classical'], logs)
    is_mihomo_updated = save_text(os.path.join(DIR_MIHOMO, sub, f"{name}.list"), res['mihomo'], logs)

    # 边界保护机制：校验是否全是 ASN，防止拿全是 ASN 的集合去硬闯 Mihomo 编译器
    valid_mrs_lines = [line for line in res['mihomo'] if not line.startswith('IP-ASN')]
    
    if not valid_mrs_lines:
        logs.append(f"  ⏭️ [跳过编译] 该规则集只有 ASN 规则，无缝适配 text 格式即可。")
    else:
        txt_path = os.path.join(DIR_MIHOMO, sub, f"{name}.list")
        mrs_path = os.path.join(DIR_MRS, sub, f"{name}.mrs")
        mihomo_rule_type = 'domain' if rtype == 'domain' else 'ipcidr'
        
        # 智能省流机制：只在源文本发生实质变更，或 MRS 文件不慎丢失时，才动用 CPU 算力重新编译
        if is_mihomo_updated or not os.path.exists(mrs_path):
            if os.path.exists(txt_path): 
                compile_to_mrs(txt_path, mrs_path, mihomo_rule_type, logs)
        else:
            logs.append(f"  ⏭️ [跳过编译] MRS 源文件无变更: {os.path.basename(mrs_path)}")
        
    # 执行完毕，将收集好的整块日志返回给主控打印
    return task_failed_urls, '\n'.join(logs)

# ================= 6. 中枢神经/主控制台 =================

def main():
    create_dirs()
    clean_old_error_log()

    source_list = load_sources()
    if not source_list:
        print("⚠️ 任务列表为空或 sources.yaml 挂了，脚本安全退出。")
        return
    
    print(f"🚀 架构核心点火：共挂载 {len(source_list)} 个编译任务，多线程狂飙模式 ON ...")
    
    all_failed_urls = []

    # 启用线程池并发引擎 (max_workers=4 榨干 GitHub Actions 的双核 CPU)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_item = {executor.submit(process_single_task, item): item for item in source_list}
        
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            try:
                # 接收执行结果，并执行原子级屏幕打印
                failed, task_log_block = future.result()
                print(task_log_block)
                if failed:
                    all_failed_urls.extend(failed)
            except Exception as exc:
                print(f"\n❌ [致命异常] 模块 {item['name']} 当场熔断: {exc}")
                all_failed_urls.extend(item['url'] if isinstance(item['url'], list) else [item['url']])

    # 收尾汇总与战损报告
    if all_failed_urls:
        with open(ERROR_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("下载或处理失败的上游源地址 (战损名单)：\n" + '\n'.join(all_failed_urls))
        print(f"\n⚠️ 脚本结束，有 {len(all_failed_urls)} 个源战死沙场，详情请查阅 error.txt")
    else:
        print("\n🎉 架构师使命达成：所有规则清洗、去重、黑名单绞杀与二进制编译完美落幕！")

if __name__ == "__main__":
    main()