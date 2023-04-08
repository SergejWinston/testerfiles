import json, re, sys, threading, time, traceback, colorama, lxml.html.diff, lxml.etree

from vkstreaming import Streaming

from config import start_offset, SEARCH, slovar, MIN_MEMBERS_COUNT
from helpers import SimpleThread, accounts, error_log, read_file_int, VkApiException, log, AuthType, BannedException

lock = threading.Lock()
stopped = False
find_link = re.compile("vk.me/join/[a-z0-9A-Z-/_+=]+")
ids_spammed = set(read_file_int("out/spammed.txt"))
ids = [i for i in read_file_int("config/groupids.txt") if i not in ids_spammed]
parsed_links = {i.rstrip('\n') for i in open("out/links.txt")}
start_length = len(ids)

def get_keyworkds():
    keyword = open('russian.txt', encoding='utf-8').read().split('\n')
    for i in keyword: yield i
    for i1 in keyword:
        for i2 in keyword:
            if i1 != i2: yield f'{i1} {i2}'
    for i1 in keyword:
        for i2 in keyword:
            for i3 in keyword:
                if len({i1, i2, i3}) == 3: yield f'{i1} {i2} {i3}'
kwords = get_keyworkds()

add_offset = 3600 * 4

end_time = int(open('offset.txt').read() or time.time() + add_offset)
def next_time():
    global end_time
    with lock:
        end_time -= add_offset
        return end_time
def write_success(end_time):
    with open('offset.txt', 'w') as ff:
        ff.write(str(end_time))


class GroupsLinksWorker(SimpleThread):
    StartLength = len(parsed_links)
    def work(self):
        while 1:
            try:
                ntime = next_time()
                for offset in range(0, 1000, 200):
                    answer = self.account.api.method('newsfeed.search', q='vk.me/join', count=200, offset=offset, end_time=ntime, start_time=ntime-add_offset)['response']
                    if answer['count'] == 0: raise BannedException("Аккаунт в бане - достигнут лимит!")
                    for i in answer['items']:
                        text = i['text']
                        for link in find_link.findall(text):
                            self.on_found(link)
                    with lock:
                        print(f'Найдено {len(parsed_links) - self.StartLength}')
                        print(ntime)
                    # if len(answer['items']) < 200:
                    break
                write_success(ntime)
            except BannedException as e:
                print(f'Аккаунт {self.account.login}:{self.account.password} в бане: ', e)
                traceback.print_exc(file=sys.stderr)
                return
            except Exception as e:
                traceback.print_exc(file=sys.stderr)
    def on_found(self, link):
        with lock:
            if link in parsed_links: return
            parsed_links.add(link)
            self._add_to_spammed(link, file='out/links.txt')
from helpers import auth_accounts
auth_accounts(AuthType.Android, wait=True)

threads = [GroupsLinksWorker(index, ac) for index, ac in enumerate(accounts)]
for i in threads: i.start()
for i in threads: i.join()
