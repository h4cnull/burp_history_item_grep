#coding=utf=8

import re
import sys
import base64
from xml.dom.minidom import parse

'''
导出burp proxy history中筛选的item为xml文件，解析响应，从中搜索域名、邮箱、IP、11位号码以帮助发现敏感信息。
'''

def domain_filter(response_data):
    return list(set(re.findall("((?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+(?:com|cn|net|org|cc|com\.cn|vip|top|xin|club|xyz|wang|xin))[^a-zA-Z]",response_data)))

def email_filter(response_data):
    return list(set(re.findall("([a-zA-Z0-9][-a-zA-Z0-9_\.]{0,62}@(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+(?:com|cn|net|org|cc|com\.cn|vip|top|xin|club|xyz|wang|xin))[^a-zA-Z]",response_data)))

def ip_filter(response_data):
    return list(set(re.findall("[^\d]((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[^d]",response_data)))

def phone_filter(response_data):
    return list(set(re.findall("[^\d]([01][\d]{2}[ -]?[\d]{4}[ -]?[\d]{4})[^\d]", response_data)))

def dir_filter(response_data):
    #令人蛋疼的内存处理机制? 毛病remove? 还必须新建列表的内存来存储新数据？ 目录匹配排除不能用作文件名的字符、以及不太可能作为目录的字符或者是它们会被urlencode
    #多匹配
    dirs = list(set(re.findall("\"((?:/[^/\\\\:\*\"\<\>\|\?,()'+$ ]+)+/?)\"", response_data)))
    dirs = dirs + list(set(re.findall("'((?:/[^/\\\\:\*\"\<\>\|\?,()'+$ ]+)+/?)'", response_data)))   #js中可能存在'/abc/def' 这样的目录
    dirs = dirs + list(set(re.findall("href=\"((?:[^/\\\\:\*\"\<\>\|\?,()'+$ ]+)+/?)\"", response_data)))  #href可能存在不以/开头写法的目录
    #dirs = dirs + list(set(re.findall("([CDEFGH]:\\\\(?:[^/\\\\:\*\"\<\>\|\?,()'+$ ]+\\\\?)+)", response_data)))  #报错页面可能存在绝对路径泄露 多余的过滤

    tmp = []
    for dir in dirs:
        if re.match("^/.*\.jpg$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.png$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.css$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.jpeg$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.gif$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.ico$",dir):
            tmp.append(dir)
    for dir in dirs:
        if re.match("^/.*\.js$",dir):
            tmp.append(dir)
    dirs = list(set(dirs) - set(tmp))
    return dirs

def all_filter(response_data):
    return domain_filter(response_data) + email_filter(response_data) + ip_filter(response_data) + phone_filter(response_data) + dir_filter(response_data)

def data_parse(url,response_data,data_filter):
    global domain_blacklist
    results = []
    if data_filter == 'all':
        results = all_filter(response_data)
    elif data_filter == 'domain':
        results = domain_filter(response_data)
    elif data_filter == 'email':
        results = email_filter(response_data)
    elif data_filter == 'ip':
        results = ip_filter(response_data)
    elif data_filter == 'phone':
        results = phone_filter(response_data)
    elif data_filter == 'dir':
        results = dir_filter(response_data)
    if results:
        print("\nURL:"+url)
        for info in results:
            if info in domain_blacklist:
                continue
            print(info)

if __name__ == '__main__':
    burp_history_item = None
    data_filter = None
    domain_blacklist = []
    with open("domain_blacklist.txt",'r',encoding='utf-8') as f:
        domain_blacklist = [line.strip() for line in f.readlines()]
    try:
        burp_history_item = sys.argv[1]
        data_filter = sys.argv[2]
    except:
        pass

    if not burp_history_item or data_filter not in ['domain','email','ip','phone','dir','all']:
        print("\n[+] Usage: python3 %s burp_item_xml_file filter\n[+] Filter:\n"
              "\tdomain\tonly grep domain\n"
              "\tip\tonly grep ip\n"
              "\tdir\tonly grep directory\n"
              "\temail\tonly grep email\n"
              "\tphone\tonly grep phone\n"
              "\tall\tgrep all\n" % sys.argv[0])
        sys.exit(0)
    try:
        DomTree = parse(sys.argv[1])
        collection = DomTree.documentElement
        items = collection.getElementsByTagName("item")
    except:
        print("[!] No such file or xml parse error: %s" % sys.argv[1])
        sys.exit(0)
    result = []
    for item in items:
        url = item.getElementsByTagName("url")[0].childNodes[0].data
        try:
            response_data = str(base64.b64decode(item.getElementsByTagName("response")[0].childNodes[0].data),encoding='utf-8')
        except Exception as e:
            if "list index out of range" in str(e):
                response_data = ' '
            else:
                response_data = str(base64.b64decode(item.getElementsByTagName("response")[0].childNodes[0].data))
        data_parse(url,response_data,data_filter)