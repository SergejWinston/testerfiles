import random
import re
import string
import sys
import threading
import time
import traceback

import colorama

colorama.init()
find_link = re.compile("vk.me/join/[a-z0-9A-Z-/_+]+")

from vkstreaming import Streaming


lock = threading.Lock()
def _add_to_spammed(i):
    with lock, open("out/links.txt", 'a+') as f:
        f.write(i + '\n')
def gen():
    return "".join(random.choice(string.ascii_lowercase) for _ in range(4))
def work(key, index):
    try:
        api = Streaming("streaming.vk.com", key, proxy='socks5://'+random.choice(open('config/proxies.txt').read().split('\n')))

        rules = api.get_rules()
        print(rules)
        api.del_all_rules()
        if index == 0: api.add_rules("cyrillic"+gen(), "бесед")
        elif index == 1: api.add_rules("cyrillic"+gen(), "vk me")
        elif index == 2: api.add_rules("cyrillic"+gen(), "join")
        elif index == 3: api.add_rules("cyrillic"+gen(), "присоед")
        elif index == 4: api.add_rules("cyrillic"+gen(), "чат")
        else:
            api.add_rules("cyrillic"+gen(), "join")
            api.add_rules("cy"+gen(), "vk me join")
            api.add_rules("cyf"+gen(), "join")
            api.add_rules("cypo"+gen(), "vk me")
            api.add_rules("cyzp"+gen(), "vk")
            api.add_rules("cyas"+gen(), "бесед -лс")
            api.add_rules("cyas"+gen(), "присоед")
            api.add_rules("cyas"+gen(), "вход")
            api.add_rules("cyas"+gen(), "ссылк")
            api.add_rules("cyas"+gen(), "приват")
            api.add_rules("cyas"+gen(), "вместе")
            api.add_rules("cyas"+gen(), "обсужд")

        rules = api.get_rules()
        print(key)
        for rule in rules:
            print(("{tag:15}:{value}").format(**rule))
        print('\n\n')
        @api.stream
        def my_func(event):
            print("[{}]: {}".format(event['author']['id'], event['text']))
            for i in find_link.findall(str(event['text'])):
                _add_to_spammed(i)
                print('НАШЕЛ ССЫЛКУ!!!')
        api.start()
    except Exception as e:
        print(colorama.Fore.RED)
        traceback.print_exc(file=sys.stderr)
        print(e)
        print(colorama.Fore.RESET)


index = 0
for key in open('keys.txt').read().split('\n'):
    if not key: continue
    g = threading.Thread(target=work, args=(key, index))
    g.start()
    time.sleep(5)
    index += 1
g.join()
