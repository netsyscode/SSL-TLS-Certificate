import ssl
import socket
import http.client
import csv
import json
from threading import Lock
from queue import PriorityQueue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import jsonlines

class SSLCrawler:
    def __init__(self, csv_file, max_threads=10, save_threshold=50, begin_num=0, end_num=20):
        self.csv_file = csv_file
        self.max_threads = max_threads
        self.progress = Progress()
        self.console = Console()
        self.task_queue = PriorityQueue()
        self.save_threshold = save_threshold
        self.cached_results = []
        self.begin_num = begin_num
        self.end_num = end_num
        self.completed_count = 0
        self.error_count = 0
        self.lock = Lock() # 用于保护cached_results
        
        self.load_tasks()

    def load_tasks(self):
        # 记录当前进度，以便继续从这里开始
        self.current_index = 0
        with open(self.csv_file, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if self.begin_num <= self.current_index < self.end_num:
                    if row:
                        rank, host = int(row[1]), row[2]
                        self.task_queue.put((rank, host))
                if self.current_index > self.end_num:
                    break
                self.current_index += 1

    def save_results(self):
        # 使用追加模式写入文件，以避免覆盖之前的结果
        with jsonlines.open('results.jsonl', mode='a') as writer:
            for result in self.cached_results:
                writer.write(result)
        self.cached_results = []

    def get_raw_ssl_certificate(self, host, port=443, proxy_host='127.0.0.1', proxy_port=33210, timeout=15):
        context = ssl.create_default_context()
        
        try:
            if proxy_host and proxy_port:
                proxy_conn = http.client.HTTPConnection(proxy_host, proxy_port)
                proxy_conn.set_tunnel(host, port)
                proxy_conn.connect()
                sock = proxy_conn.sock
            else:
                # 设置超时时间
                sock = socket.create_connection((host, port), timeout=timeout)

            with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                der_cert = ssl_sock.getpeercert(binary_form=True)
                return ssl.DER_cert_to_PEM_cert(der_cert)
        except socket.timeout as e1:
            raise ConnectionError(f"Timeout when connecting to {host}: {str(e1)}")

    def fetch_certificate(self, rank, host):
        try:
            
            cert = self.get_raw_ssl_certificate(host)
            result = {'rank': rank, 'host': host, 'error': None, 'certificate': None}
            if cert:
                result['certificate'] = cert
            else:
                result['error'] = 'No certificate found'
                
        except Exception as e:
            # self.console.log(f"Error fetching SSL certificate for <{host}>: {e}")
            result = {'rank': rank, 'host': host, 'error': str(e), 'certificate': None}
            
        finally:
            # 在添加到cached_results之前对结果进行排序
            
            with self.lock:  # 获取锁
                if result['error']:
                    self.error_count += 1
                else:
                    self.completed_count += 1
                self.cached_results.append(result)
                self.cached_results.sort(key=lambda x: x['rank'])
                if len(self.cached_results) >= self.save_threshold:
                    self.save_results()
        self.progress.update(self.progress_task, description=f"[green]Completed: {self.completed_count}, [red]Errors: {self.error_count}")
        self.progress.advance(self.progress_task)

    def start_crawling(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:
            self.progress_task = self.progress.add_task("[Waiting]", total=self.end_num - self.begin_num)

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                while not self.task_queue.empty():
                    index, host = self.task_queue.get()
                    future = executor.submit(self.fetch_certificate, index, host)
                    futures.append(future)

                # 等待所有线程完成
                for future in as_completed(futures):
                    pass  # 可以在此处处理每个future的结果，如果需要

        # 确保所有线程完成后再保存剩余结果
        if self.cached_results:
            self.save_results()
        
        self.console.log(f"Saving {len(self.cached_results)} results...")
        self.console.log(f"Completed: {self.completed_count}, Errors: {self.error_count}")

if __name__ == "__main__":
    crawler = SSLCrawler(csv_file='top-1m.csv', max_threads=100, save_threshold=200, begin_num=0, end_num=100000)
    crawler.start_crawling()
