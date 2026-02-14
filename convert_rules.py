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
        "policy": "🎠 私有地址", # 这是给 Quantumult X 用的策略组名称
        "type": "domain",        # 标记这个文件是域名列表
        "strict": True           # 开启严格模式  False = 默认后缀匹配 (+.)，True = 默认精确匹配
    },
    {
        # 示例3：IP 列表源
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/private.list",
        "name": "private_ip",
        "policy": "🎠 私有地址",
        "type": "ip",            # 标记这个文件是 IP 列表
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ntp.list",
        "name": "ntp_domain",
        "policy": "🕰️ NTP",
        "type": "domain",
        "strict": True
    },
    {
        # 示例2：去广告/混合源（通常只写 baidu.com 但隐含意思是杀全家）
        # 建议关闭 strict: False，这样所有纯域名都会被视为“后缀匹配”，防止漏杀子域名
        "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-clash.yaml",
        "name": "block_domain",
        "policy": "⛔️ 广告|阻断",
        "type": "domain",
        "strict": False          # 关闭严格模式（默认推荐）
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/cn_dns_domains.list",
        "name": "cn_dns_domain",
        "policy": "🔺 国内DNS",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/cn_dns_ips.list",
        "name": "cn_dns_ip",
        "policy": "🔺 国内DNS",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/global_dns_domains.list",
        "name": "global_dns_domain",
        "policy": "🔸™️国外DNS",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/global_dns_ips.list",
        "name": "global_dns_ip",
        "policy": "🔸™️国外DNS",
        "type": "ip",
        "strict": True
    },
    # ======================================================== 下载与P2P
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-pt.list",
        "name": "pt_domain",
        "policy": "📦 PT",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/pt.list",
        "name": "pt_ip",
        "policy": "📦 PT",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-public-tracker.list",
        "name": "p2p_domain",
        "policy": "🍻 BT/P2P",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/Inner.yaml",
        "name": "inner_custom",
        "policy": "☀️ 自定-内",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/Outer.yaml",
        "name": "outer_custom",
        "policy": "☄️™️自定-外",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/xunlei.list",
        "name": "xunlei_domain",
        "policy": "🦌 迅雷",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-game-platforms-download.list",
        "name": "gamedownload_domain",
        "policy": "🕹️ 游戏下载",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games@cn.list",
        "name": "games@cn_domain",
        "policy": "🎮 国际游戏中区CDN",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 国内视频与媒体
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bilibili-cdn@!cn.list",
        "name": "bilibiligat_domain",
        "policy": "🐨™️Bilibili 海外",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bilibili.list",
        "name": "bilibili_domain",
        "policy": "🐨 Bilibili",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/cctv.list",
        "name": "cctv_domain",
        "policy": "📺 CCTV",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/hunantv.list",
        "name": "mgtv_domain",
        "policy": "🥭 芒果TV",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/iqiyi.list",
        "name": "iqiyi_domain",
        "policy": "🥝 爱奇艺",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/douyu.list",
        "name": "douyu_domain",
        "policy": "🦈 斗鱼",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/douyin.list",
        "name": "douyin_domain",
        "policy": "🎵 抖音",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/kuaishou.list",
        "name": "kuaishou_domain",
        "policy": "📸 快手",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 腾讯与电商系    
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tencent@!cn.list",
        "name": "tencent@!cn_domain",
        "policy": "🐧™️腾讯国际",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/suning.list",
        "name": "suning_domain",
        "policy": "🦁 苏宁",
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
    # ======================================================== 其他国内大厂
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/baidu.list",
        "name": "baidu_domain",
        "policy": "🐻‍❄️ 百度",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/sina.list",
        "name": "sina_domain",
        "policy": "👁️ 新浪",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/huawei.list",
        "name": "huawei_domain",
        "policy": "🦚 华为",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/qihoo360.list",
        "name": "qihoo360_domain",
        "policy": "🐯 奇虎360",
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
    # ======================================================== 运营商
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
    # ======================================================== 银行
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/icbc.list",
        "name": "icbc_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/boc.list",
        "name": "boc_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/ccb.list",
        "name": "ccb_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/cmb.list",
        "name": "cmb_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/pingan.list",
        "name": "pingan_domain",
        "policy": "🏦 银行",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/citic.list",
        "name": "citic_domain",
        "policy": "🏦 银行",
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
    # ======================================================== 泛规则分类
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-media-cn.list",
        "name": "media-cn_domain",
        "policy": "🍞 中文传媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-cn.list",
        "name": "socialmedia-cn_domain",
        "policy": "🍉 中文社媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-entertainment-cn.list",
        "name": "entertainment-cn_domain",
        "policy": "🍋 国内娱乐",
        "type": "domain",
        "strict": True
    },
    # ======================================================== AI 服务
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ai-!cn.list",
        "name": "ai!cn_domain",
        "policy": "🔆™️国外AI",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple-intelligence.list",
        "name": "apple-intelligence_domain",
        "policy": "🍎™️Apple智能",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games-!cn.list",
        "name": "games-!cn_domain",
        "policy": "🎮™️游戏国际",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 开发者服务
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev-cn.list",
        "name": "dev-cn_domain",
        "policy": "🥥 中区开发者",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev@cn.list",
        "name": "dev@cn_domain",
        "policy": "🥥 全球开发者中国CDN",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/github1s.list",
        "name": "github1s_domain",
        "policy": "🥥™️Github1s",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-dev.list",
        "name": "dev_domain",
        "policy": "🥥™️全球开发者",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 苹果
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple-cn.list",
        "name": "apple-cn_domain",
        "policy": "🍏 Apple中国CDN",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple@cn.list",
        "name": "apple@cn_domain",
        "policy": "🍏 Apple中国",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple.list",
        "name": "apple_domain",
        "policy": "🍎™️Apple",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo-lite/geoip/apple.list",
        "name": "apple_ip",
        "policy": "🍎™️Apple",
        "type": "ip",
        "strict": True
    },
    # ======================================================== 微软
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/onedrive.list",
        "name": "onedrive_domain",
        "policy": "☁️™️OneDrive",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bing.list",
        "name": "bing_domain",
        "policy": "🍍™️Bing",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft@cn.list",
        "name": "microsoft@cn_domain",
        "policy": "Ⓜ️ 微软中国",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft.list",
        "name": "microsoft_domain",
        "policy": "Ⓜ️™️微软",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 谷歌
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.list",
        "name": "google_domain",
        "policy": "🧀™️Google",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/google.list",
        "name": "google_ip",
        "policy": "🧀™️Google",
        "type": "ip",
        "strict": False
    },
    # ======================================================== 国际社交
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/telegram.list",
        "name": "telegram_domain",
        "policy": "📮™️Telegram",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/telegram.list",
        "name": "telegram_ip",
        "policy": "📮™️Telegram",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/twitter.list",
        "name": "twitter_ip",
        "policy": "🍉™️外文社媒",
        "type": "ip",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/dcard.list",
        "name": "dcard_domain",
        "policy": "🍀™️Dcard",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-!cn.list",
        "name": "socialmedia-!cn_domain",
        "policy": "🍉™️外文社媒",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 金融与加密
    {
        "url": "https://raw.githubusercontent.com/wanfc/rule/refs/heads/main/BitgetWallet.yaml",
        "name": "bitget_domain",
        "policy": "💶™️加密货币",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-cryptocurrency@cn.list",
        "name": "crypto@cn_domain",
        "policy": "💶 国内加密货币",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-cryptocurrency.list",
        "name": "crypto_domain",
        "policy": "💶™️加密货币",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/paypal@cn.list",
        "name": "paypal@cn_domain",
        "policy": "💳 贝宝",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/paypal.list",
        "name": "paypal_domain",
        "policy": "💳™️PayPal",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 杂项
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-password-management.list",
        "name": "password_domain",
        "policy": "🧰™️Password",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adguard.list",
        "name": "adguard_domain",
        "policy": "💊™️Adguard",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adobe-activation.list",
        "name": "adobe-activation_domain",
        "policy": "🖍️™️Adobe激活",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/adobe.list",
        "name": "adobe_domain",
        "policy": "🖍️™️Adobe",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/nvidia.list",
        "name": "nvidia_domain",
        "policy": "💡™️Nvidia",
        "type": "domain",
        "strict": True
    },
    # ======================================================== 兜底防御
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-media.list",
        "name": "media_domain",
        "policy": "🍞™️外文传媒",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-entertainment.list",
        "name": "entertainment_domain",
        "policy": "🍋™️国外娱乐",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-porn.list",
        "name": "porn_domain",
        "policy": "🔞™️NSFW",
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/cn.list",
        "name": "cn_domain",
        "policy": "🏰 中国1️⃣",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/geolocation-!cn.list",
        "name": "geo-!cn_domain",
        "policy": "🛫™️GEO国外",
        "type": "domain",
        "strict": True
    },
    {
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/cn.list",
        "name": "cn_ip",
        "policy": "🏰 中国2️⃣",
        "type": "ip",
        "strict": True
    },
]

# 定义三个顶层目录，对应不同的软件需求
DIR_QX = "QuantumultX"     # QX 专用：HOST 格式
DIR_CLASSICAL = "Classical" # 经典版：DOMAIN-SUFFIX 格式 (含 no-resolve)
DIR_MIHOMO = "Mihomo"       # Mihomo 专用：符合 behavior: domain/ipcidr 的 text 格式
ERROR_LOG_FILE = "error.txt"

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
    print("🚀 脚本启动：执行多格式规则转换...")
    
    failed_urls = []

    # 核心循环
    for item in SOURCE_LIST:
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