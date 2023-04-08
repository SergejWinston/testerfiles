import json
import re
import sys
import threading
import time
import traceback

import colorama
import lxml.html.diff
import lxml.etree
from vk_api import VkApiError
from vkstreaming import Streaming

from config import start_offset, SEARCH, slovar
from helpers import SimpleThread, accounts, error_log, read_file_int, auth_accounts

lock = threading.Lock()
stopped = False
find_link = re.compile("vk.me/join/[a-z0-9A-Z-/_]+")
parsed_links = set()
count_parsed = 0
query = "vk.me/join " + next(slovar)
class Worker(SimpleThread):

    def work(self):
        global stopped, count_parsed, query
        for i in range(1000):
            with lock:
                offset = start_offset[0]
                start_offset[0] += 30
            start_q = query
            try:
                data = self.account.api.session.post(
                    "https://m.vk.com/search",
                    params={
                        'c[section]': 'statuses',
                        'c[q]': start_q,
                        'offset': offset
                    },
                    data={"_ajax": 1},
                    headers={"X-Requested-With": "XMLHttpRequest"}
                ).json()
                html = data['data'][0]
                document = lxml.html.fromstring(html)
                for element in document.cssselect(".wall_item .wi_body"):
                    data_el = element.text_content()
                    self._add_to_spammed(json.dumps(data_el), file="answer.json_data")
                    for string in find_link.findall(data_el):
                        if string not in parsed_links:
                            parsed_links.add(string)
                            self._add_to_spammed(string, file='out/links.txt')
                            with lock:
                                count_parsed += 1


                with lock:
                    print(f"Нашел {count_parsed} ссылок со смещением {offset}",
                          end='\r' if count_parsed % 300 not in range(0, 10) else '\n')
                    self._add_to_spammed(offset, file="offsets.txt")
                time.sleep(3)
            except lxml.etree.ParserError as e:
                if 'is empty' in str(e):
                    with lock:
                        print(f"{colorama.Fore.MAGENTA}Аккаунт {self.account} уткнулся в лимит...{colorama.Fore.RESET}")
                        print(f"Нашел {count_parsed} ссылок со смещением {offset} по запросу {start_q}",
                              end='\r' if offset % 300 == 250 else '\n')
                        if query == start_q and start_offset[0] >= 690:
                            query = "vk.me/join " + next(slovar)
                            start_offset[0] = 0
                else:
                    print(f"Произошла неизвестная ошибка: {e}")
                    traceback.print_exc(file=sys.stderr)
            except Exception as e:
                with lock:
                    print(f"Произошла неизвестная ошибка: {e}")
                    traceback.print_exc(file=sys.stderr)
    def _parse_items(self, items):
        c = 0
        for i in items:
            text = i['text']
            links = set(find_link.findall(text))
            c += len(links)
            for link in links: self._add_to_spammed(link)
        return c


auth_accounts()

threads = [Worker(index, ac) for index, ac in enumerate(accounts)]
for i in threads: i.start()
for i in threads: i.join()
