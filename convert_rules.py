import requests
import os
import re
import ipaddress
import hashlib  # 用于计算MD5，实现增量更新

# ================= 配置区域 =================
#在这里配置你需要转换的源文件。
#每个 {} 代表一个源，你可以复制粘贴添加更多。
SOURCE_LIST = [
    {
        # 示例1：Geosite 类源（通常包含 +.google.com 和 google.com）
        # 建议开启 strict: True，这样能精准区分“后缀匹配”和“精确匹配”
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/private.list",
        "name": "private_domain",
        "policy": "🎠 私有地址",  # 这是给 Quantumult X 用的策略组名称
        "type": "domain",        # 标记这个文件是域名列表
        "strict": True           # 开启严格模式
    },
    {
        # 示例2：去广告/混合源（通常只写 baidu.com 但隐含意思是杀全家）
        # 建议关闭 strict: False，这样所有纯域名都会被视为“后缀匹配”，防止漏杀子域名
        # "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-clash.yaml",
        # "name": "anti_ad",
        # "policy": "🆎 广告",
        # "type": "domain",
        # "strict": False          # 关闭严格模式（默认推荐）
    },
    {
        # 示例3：IP 列表源
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/private.list",
        "name": "private_ip",
        "policy": "🎠 私有地址",
        "type": "ip",            # 标记这个文件是 IP 列表
        "strict": False
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tracker.list",
        "name": "tracker_domain",
        "policy": "⛓️ Tracker",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-public-tracker.list",
        "name": "public-tracker_domain",
        "policy": "⛓️ Tracker",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-pt.list",
        "name": "pt_domain",
        "policy": "📦 PT",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-speedtest.list",
        "name": "speedtest_domain",
        "policy": "🎰 Speedtest",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev-cn.list",
        "name": "cd-cn_domain",
        "policy": "🥝 中区开发者",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev%40cn.list",
        "name": "cd@cn_domain",
        "policy": "🥝 全球开发者中国CDN",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev.list",
        "name": "cd_domain",
        "policy": "🥝 全球开发者",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/github1s.list",
        "name": "github1s_domain",
        "policy": "🥥 Github1s",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple-intelligence.list",
        "name": "apple-intelligence_domain",
        "policy": "🍎 Apple智能",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple-cn.list",
        "name": "apple-cn_domain",
        "policy": "🍏 Apple中国CDN",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple%40cn.list",
        "name": "apple@cn_domain",
        "policy": "🍏 Apple中国",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple.list",
        "name": "apple_domain",
        "policy": "🍎 Apple",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo-lite/geoip/apple.list",
        "name": "apple_ip",
        "policy": "🍎 Apple",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ai-!cn.list",
        "name": "ai-!cn_domain",
        "policy": "🔆 国外AI",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ai-cn.list",
        "name": "aicn_domain",
        "policy": "🔅 国内AI",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tencent%40!cn.list",
        "name": "tencent@!cn_domain",
        "policy": "🐧 腾讯国际",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tencent.list",
        "name": "tencent_domain",
        "policy": "🐧 腾讯",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/alibaba.list",
        "name": "alibaba_domain",
        "policy": "🐹 阿里巴巴",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/jd.list",
        "name": "jd_domain",
        "policy": "🐶 京东",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/pinduoduo.list",
        "name": "pinduoduo_domain",
        "policy": "🦊 拼多多",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/meituan.list",
        "name": "meituan_domain",
        "policy": "🍟 美团",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/didi.list",
        "name": "didi_domain",
        "policy": "🚕 滴滴",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/baidu.list",
        "name": "baidu_domain",
        "policy": "🐻‍❄️ 百度",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/qihoo360.list",
        "name": "qihoo360_domain",
        "policy": "🐯 奇虎360",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/onedrive.list",
        "name": "onedrive_domain",
        "policy": "☁️ OneDrive",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bing.list",
        "name": "bing_domain",
        "policy": "🍍 Bing",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/netease.list",
        "name": "netease_domain",
        "policy": "🦀 网易",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/huawei.list",
        "name": "huawei_domain",
        "policy": "🦚 华为",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/kingsoft.list",
        "name": "kingsoft_domain",
        "policy": "🏖️ 金山软件",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/xiaomi.list",
        "name": "xiaomi_domain",
        "policy": "🍥 小米",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-bank-cn.list",
        "name": "bank-cn_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-password-management.list",
        "name": "password_domain",
        "policy": "🧰 Password",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/paypal%40cn.list",
        "name": "paypal@cn_domain",
        "policy": "💳 贝宝",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/paypal.list",
        "name": "paypal_domain",
        "policy": "💳 PayPal",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-cryptocurrency%40cn.list",
        "name": "crypto@cn_domain",
        "policy": "💶 国内加密货币",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-cryptocurrency.list",
        "name": "crypto_domain",
        "policy": "💶 加密货币",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/chinamobile.list",
        "name": "chinamobile_domain",
        "policy": "📡 运营商",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/chinatelecom.list",
        "name": "chinatelecom_domain",
        "policy": "📡 运营商",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/chinaunicom.list",
        "name": "chinaunicom_domain",
        "policy": "📡 运营商",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/chinabroadnet.list",
        "name": "chinabroadnet_domain",
        "policy": "📡 运营商",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/chinatower.list",
        "name": "chinatower_domain",
        "policy": "📡 运营商",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/telegram.list",
        "name": "telegram_domain",
        "policy": "📮 Telegram",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/telegram.list",
        "name": "telegram_ip",
        "policy": "📮 Telegram",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adguard.list",
        "name": "adguard_domain",
        "policy": "💊 Adguard",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-media-cn.list",
        "name": "cm-cn_domain",
        "policy": "🍞 中文传媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-media.list",
        "name": "cm_domain",
        "policy": "🍞 外文传媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/dcard.list",
        "name": "dcard_domain",
        "policy": "🍀 Dcard",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-cn.list",
        "name": "csm-cn_domain",
        "policy": "🍉 中文社媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-!cn.list",
        "name": "csm-!cn_domain",
        "policy": "🍉 外文社媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/twitter.list",
        "name": "twitter_ip",
        "policy": "🍉 外文社媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/nvidia.list",
        "name": "nvidia_domain",
        "policy": "💡 Nvidia",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-game-platforms-download.list",
        "name": "gd_domain",
        "policy": "🕹️ 游戏下载",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games%40cn.list",
        "name": "games@cn_domain",
        "policy": "🎮 国际游戏中区CDN",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games-cn.list",
        "name": "games-cn_domain",
        "policy": "🎮 游戏国内",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games-!cn.list",
        "name": "games-!cn_domain",
        "policy": "🎮 游戏国际",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-entertainment-cn.list",
        "name": "ce-cn_domain",
        "policy": "🍋 国内娱乐媒体",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-entertainment.list",
        "name": "ce_domain",
        "policy": "🍋 国外娱乐媒体",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bilibili2.list",
        "name": "bilibili2_domain",
        "policy": "🍋 国内娱乐媒体",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo-lite/geoip/bilibili.list",
        "name": "bilibili_ip",
        "policy": "🍋 国内娱乐媒体",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.list",
        "name": "google_domain",
        "policy": "🧀 Google",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/google.list",
        "name": "google_ip",
        "policy": "🧀 Google",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-porn.list",
        "name": "porn_domain",
        "policy": "🔞 NSFW",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adobe-activation.list",
        "name": "adobe-jh_domain",
        "policy": "🖍️ Adobe激活",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adobe.list",
        "name": "adobe_domain",
        "policy": "🖍️ Adobe",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft%40cn.list",
        "name": "microsoft@cn_domain",
        "policy": "Ⓜ️ 微软中国",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft.list",
        "name": "microsoft_domain",
        "policy": "Ⓜ️ 微软",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/geolocation-cn.list",
        "name": "geo-cn_domain",
        "policy": "🗼 GEO国内",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/geolocation-!cn.list",
        "name": "geo-!cn_domain",
        "policy": "🛫 GEO国外",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/cn.list",
        "name": "cn_domain",
        "policy": "🏰 中国",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/cn.list",
        "name": "cn_ip",
        "policy": "🏰 中国",
        "type": "ip",
        "strict": True
    },
]

# 定义转换后文件的存放目录
DIR_QX = "QuantumultX"  # 存放给 Quantumult X 用的文件
DIR_MIHOMO = "Mihomo"   # 存放给 Mihomo/Shadowrocket/Loon 用的通用文件
ERROR_LOG_FILE = "error.txt" # 错误日志文件名

def create_dirs():
    """
    功能：检查并创建输出目录。
    如果目录不存在，就新建一个，防止保存文件时报错。
    """
    if not os.path.exists(DIR_QX):
        os.makedirs(DIR_QX)
    if not os.path.exists(DIR_MIHOMO):
        os.makedirs(DIR_MIHOMO)

def clean_old_error_log():
    """运行开始前，清理旧的错误日志"""
    if os.path.exists(ERROR_LOG_FILE):
        try:
            os.remove(ERROR_LOG_FILE)
            print(f"🧹 已清除旧的 {ERROR_LOG_FILE}")
        except Exception as e:
            print(f"⚠️ 无法清除旧日志: {e}")

def calculate_md5(text):
    """计算文本内容的 MD5 值"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def fetch_content(url):
    """
    功能：从网络下载源文件的内容。
    """
    print(f"📥 正在下载: {url}")
    try:
        # 伪装成浏览器（User-Agent），防止被某些服务器拒绝访问
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        # 发起请求，设置15秒超时，防止卡死
        resp = requests.get(url, headers=headers, timeout=15)
        # 检查是否下载成功（比如404错误会在这里被捕获）
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"❌ 下载失败 {url}: {e}")
        return None

def clean_line(line):
    """
    功能：对每一行文本进行基础清洗，去掉干扰字符。
    """
    # 1. 去除行内注释
    # 比如 "google.com # 谷歌"，只保留 "google.com"
    # 同时支持 '#' (通用) 和 '//' (编程语言风格)
    line = re.split(r'#|//', line)[0]
    
    # 2. 处理 AdGuard 风格的注释
    # AdGuard 规则通常以 '!' 开头作为注释行，直接丢弃
    if line.strip().startswith('!'):
        return ''
    
    # 3. 去除 YAML 格式的列表标记
    # 如果源文件是 YAML，行首会有 "- "，需要切掉它才能拿到里面的内容
    line = line.strip()
    if line.startswith('- '):
        line = line[1:].strip()
    
    # 4. 去除首尾的引号
    # 防止出现 'google.com' 这种带引号的情况
    line = line.strip("'").strip('"')
    
    return line

def smart_detect(content, strict_mode=False):
    """
    【核心功能】智能识别引擎
    功能：分析一行文本，判断它是什么规则（IP 还是 域名），并提取纯净的内容。
    
    参数：
      strict_mode: 是否开启严格模式。
        - True: 纯域名视为精确匹配 (DOMAIN)
        - False: 纯域名视为后缀匹配 (DOMAIN-SUFFIX) - 推荐用于去广告
    
    返回：
      (类型, 纯净值) 或者 (None, None)
    """
    content = content.strip()
    if not content: return None, None

    # ================= 阶段一：特殊软件格式解析 =================
    # 这一步专门处理 AdGuard, SmartDNS, Dnsmasq 等非标准格式

    # 1. 过滤 AdGuard/EasyList 的白名单规则
    # 我们做的是拦截/分流列表，白名单(@@)混进来会导致冲突，直接丢弃
    if content.startswith('@@') or '##' in content or '#@#' in content:
        return None, None
        
    # 2. 提取 AdGuard 拦截规则 (||example.com^)
    # 提取 || 和 ^ 中间的部分作为域名
    if content.startswith('||'):
        content = content[2:].split('^')[0]
    
    # 3. 提取 SmartDNS 配置 (address /example.com/#)
    elif content.startswith('address') and '/' in content:
        parts = content.split('/')
        # 只有格式正确（包含两个/）才提取中间部分
        if len(parts) >= 2:
            content = parts[1].strip()

    # 4. 提取 Dnsmasq 配置 (address=/example.com/)
    elif content.startswith('address=') and '/' in content:
        parts = content.split('/')
        if len(parts) >= 2:
            content = parts[1].strip()

    # ================= 阶段二：标准前缀解析 =================
    # 处理像 DOMAIN-SUFFIX,google.com 这种标准写法

    if ',' in content:
        parts = content.split(',', 1)
        prefix = parts[0].strip().upper()
        rest = parts[1].strip()
        
        # 二次切割：防止后面还跟着策略名 (如 "google.com, Proxy")
        # 我们只取第一个逗号前的内容，保证提取到的是纯域名/IP
        if ',' in rest: 
            value = rest.split(',', 1)[0].strip()
        else: 
            value = rest
            
        # 清理可能残留的 "no-resolve" 标记
        value = re.sub(r'\s*no-resolve', '', value, flags=re.IGNORECASE).strip()

        # 白名单匹配：只保留我们认识的类型，其他的(如 USER-AGENT)一律丢弃
        if 'IP-CIDR6' in prefix: return 'ipv6', value
        if 'IP-CIDR' in prefix: return 'ipv4', value 
        if 'SUFFIX' in prefix: return 'domain-suffix', value
        if 'DOMAIN' in prefix or 'HOST' in prefix: return 'domain', value
        
        # 如果前缀不在上面这几行里，说明是垃圾数据，丢弃
        return None, None

    # ================= 阶段三：纯文本智能探测 =================
    # 处理像 "google.com" 或 "1.1.1.1" 这种无前缀的写法

    # 1. 安全检查：如果包含非法字符，说明不是纯域名/IP，丢弃
    # 比如包含 * (通配符)、= (赋值)、/ (路径) 等，通常是正则或没清洗干净的垃圾
    if any(char in content for char in ['/', '*', '=', '|', ':', '(', ')', '[', ']']):
        return None, None

    # 2. 尝试识别是否为 IP 地址
    try:
        net = ipaddress.ip_network(content, strict=False)
        if net.version == 4: return 'ipv4', str(net)
        elif net.version == 6: return 'ipv6', str(net)
    except ValueError:
        pass # 不是 IP，继续往下走

    # 3. 处理带点的域名后缀写法
    # Meta/Surge 格式：+.google.com -> 域名后缀
    if content.startswith('+.'): 
        return 'domain-suffix', content[2:]
    
    # 4. 处理以点开头的域名
    # .google.com -> 域名后缀
    if content.startswith('.'): 
        return 'domain-suffix', content[1:]
    
    # 5. 处理纯域名 (google.com)
    # 必须包含点号且没有空格
    if ' ' not in content and '.' in content:
        if strict_mode:
            return 'domain', content       # 严格模式：精确匹配
        else:
            return 'domain-suffix', content # 默认模式：后缀匹配 (更安全)

    # 如果以上都不是，视为无效数据
    return None, None

def process_rules(content, target_type, policy_name, strict_mode):
    """
    功能：循环处理源文件的每一行，分类并生成最终规则。
    """
    # 存放 Quantumult X 的规则列表
    qx_lines = []
    qx_nr_lines = [] # no-resolve 版本
    
    # 存放 Mihomo/通用 的规则列表
    mihomo_lines = []
    mihomo_nr_lines = []

    lines = content.splitlines()
    for line in lines:
        # 第一步：清洗行
        line = clean_line(line)
        if not line: continue
        
        # 跳过文件头的一些无用元数据
        if line.lower().startswith(('payload:', 'version:', 'address', '#')): 
            continue

        # 第二步：智能识别
        detected_type, value = smart_detect(line, strict_mode)
        
        # 如果识别失败（返回None），直接跳过该行
        if not detected_type: continue
        
        # 第三步：类型筛选（纯净度保证）
        # 如果我们需要 Domain 文件，却识别出了 IP，跳过
        if target_type == 'domain' and detected_type in ['ipv4', 'ipv6']: continue
        # 如果我们需要 IP 文件，却识别出了 Domain，跳过
        if target_type == 'ip' and detected_type in ['domain', 'domain-suffix']: continue

        # 第四步：格式化输出
        # 根据识别到的类型，分别生成 QX 和 Mihomo 需要的格式

        # === IPv4 ===
        if detected_type == 'ipv4':
            # QX: 必须带策略名
            qx_lines.append(f"ip-cidr, {value}, {policy_name}")
            qx_nr_lines.append(f"ip-cidr, {value}, {policy_name}, no-resolve")
            # Mihomo: 只要规则，不带策略名
            mihomo_lines.append(f"IP-CIDR,{value}")
            mihomo_nr_lines.append(f"IP-CIDR,{value},no-resolve")

        # === IPv6 ===
        elif detected_type == 'ipv6':
            # QX: 关键字是 ip6-cidr
            qx_lines.append(f"ip6-cidr, {value}, {policy_name}")
            qx_nr_lines.append(f"ip6-cidr, {value}, {policy_name}, no-resolve")
            # Mihomo: 关键字是 IP-CIDR6
            mihomo_lines.append(f"IP-CIDR6,{value}")
            mihomo_nr_lines.append(f"IP-CIDR6,{value},no-resolve")

        # === 域名后缀 (DOMAIN-SUFFIX) ===
        elif detected_type == 'domain-suffix':
            # QX: 关键字是 HOST-SUFFIX
            qx_lines.append(f"HOST-SUFFIX, {value}, {policy_name}")
            # Mihomo: 关键字是 DOMAIN-SUFFIX
            mihomo_lines.append(f"DOMAIN-SUFFIX,{value}")

        # === 精确域名 (DOMAIN) ===
        elif detected_type == 'domain':
            # QX: 关键字是 HOST
            qx_lines.append(f"HOST, {value}, {policy_name}")
            # Mihomo: 关键字是 DOMAIN
            mihomo_lines.append(f"DOMAIN,{value}")

    # 将分类好的结果打包返回
    return {
        "qx": qx_lines, "qx_nr": qx_nr_lines,
        "mihomo": mihomo_lines, "mihomo_nr": mihomo_nr_lines
    }

def save_text(path, lines):
    """
    优化后的保存逻辑：
    只有当内容发生变化时才写入，否则跳过。
    """
    if not lines: return
    
    new_content = '\n'.join(lines)
    
    # 检查本地是否有旧文件
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                old_content = f.read()
            
            # 对比 MD5 (也可以直接对比字符串，MD5效率在超大文件时略高，这里主要是逻辑清晰)
            if calculate_md5(new_content) == calculate_md5(old_content):
                print(f"  ⚠️ 内容未变，跳过写入: {os.path.basename(path)}")
                return # 直接退出，不写入
        except Exception:
            pass # 如果读取旧文件出错，就当它不存在，继续覆盖

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"  💾 已更新文件: {path} (共 {len(lines)} 条规则)")
    except Exception as e:
        print(f"  ❌ 保存失败 {path}: {e}")

def main():
    """
    主程序入口
    """
    # 1. 准备目录
    create_dirs()
    # 🆕 [新增] 运行前清理旧错误日志
    clean_old_error_log() 
    print("🚀 开始执行转换脚本...")
    
    failed_urls = [] # 🆕 [新增] 用于存储失败的 URL

    # 2. 遍历配置列表，逐个处理
    for item in SOURCE_LIST:
        url = item['url']
        name = item['name']
        policy = item['policy']
        req_type = item['type'] 
        # 获取 strict 参数，如果没有设置，默认为 False
        is_strict = item.get('strict', False)
        
        print(f"\n--------------------------------")
        print(f"正在处理: [{name}]")
        print(f"  - 类型: {req_type}")
        print(f"  - 策略: {policy}")
        print(f"  - 严格模式: {'开启' if is_strict else '关闭'}")
        
        # 下载内容
        content = fetch_content(url)
        
        if not content:
            # 🆕 [修改] 容灾逻辑
            # 如果下载失败：
            # 1. 记录 URL 到失败列表
            # 2. 打印提示：保留旧文件
            # 3. continue 跳过，不执行 save_text，这样硬盘上的旧文件就不会被修改或删除
            print(f"  🛡️ 触发容灾：保留本地旧文件 (如果存在)")
            failed_urls.append(url)
            continue 
        
        # 核心转换
        res = process_rules(content, req_type, policy, is_strict)
        
        # === 保存文件 ===
        # 1. 保存 Quantumult X 格式 (带策略名)
        save_text(os.path.join(DIR_QX, f"{name}.list"), res['qx'])
        if req_type == 'ip':
            save_text(os.path.join(DIR_QX, f"{name}_no-resolve.list"), res['qx_nr'])

        # 2. 保存 Mihomo/通用 格式 (无策略名)
        save_text(os.path.join(DIR_MIHOMO, f"{name}.list"), res['mihomo'])
        if req_type == 'ip':
            save_text(os.path.join(DIR_MIHOMO, f"{name}_no-resolve.list"), res['mihomo_nr'])

    # 🆕 [新增] 脚本结束前，检查是否有失败记录
    if failed_urls:
        print(f"\n⚠️ 警告：有 {len(failed_urls)} 个源处理失败，已写入 {ERROR_LOG_FILE}")
        try:
            with open(ERROR_LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("以下源地址下载或处理失败 (保留了旧规则)：\n")
                f.write('\n'.join(failed_urls))
        except Exception as e:
            print(f"❌ 无法写入错误日志: {e}")
    else:
        print("\n🎉 所有任务处理完成，无错误！")

if __name__ == "__main__":
    main()
