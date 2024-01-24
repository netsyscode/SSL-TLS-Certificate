
import os
import ssl
import socket
import http.client
import csv
import json
import jsonlines
from threading import Lock
from queue import PriorityQueue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ProcessPoolExecutor, Future
from socket import socket
from datetime import datetime
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from func_timeout import func_set_timeout, FunctionTimedOut, dafunc
from ..logger.logger import my_logger



class Crawler:
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
        self.scan_status_data = 
        self.load_tasks()


    def get_status() 

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
        with jsonlines.open('results.jsonl', mode='a') as writer:
            for result in self.cached_results:
                writer.write(result)
        self.cached_results = []

    def get_raw_ssl_certificate(self, host, port=443, proxy_host='127.0.0.1', proxy_port=33210, timeout=15):
        context = ssl.create_default_context()

        sock = socket()
        sock.pro
        sock.settimeout(timeout)
        sock.setblocking(True)  # 关键
        sock.connect((hostname, port), )

        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE)

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_tlsext_host_name(hostname.encode())  # 关键: 对应不同域名的证书
        sock_ssl.set_connect_state()
        sock_ssl.do_handshake()

        # self.cert = sock_ssl.get_peer_certificate()
        certs = sock_ssl.get_peer_cert_chain()  # 下载证书
        # print("OK")
        sock_ssl.close()
        sock.close()
        cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
        return cert_pem
    except Exception as e:
        my_logger.error(f"Error fetching certificate for {hostname}: {e}")



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

    def start(self):
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


    def stop(self):
        pass


def create_cert_mapping_json(url_cert_mapping, json_filename):
    with open(json_filename, 'w') as json_file:
        json.dump(url_cert_mapping, json_file, indent=4)
    json_file.close()



def concurrentScanner(url_list : list[str], start_index : int):

    timestamp = datetime.now().strftime("%Y%m%d")
    output_directory = "output"
    output_directory = os.path.join(output_directory, f"{timestamp}")
    os.makedirs(output_directory, exist_ok=True)

    max_certs_per_batch = 2000
    url_cert_mapping = []
    cert_counter = 0

    for url in url_list:
        try:
            cert_chain_as_pem_str = get_certificate_chain(url)
        except (FunctionTimedOut, dafunc.FunctionTimedOut) as e:
            # print(f"Fetching certificate for {url} time out")
            cert_chain_as_pem_str = []
        except Exception as e:
            # print(f"Error fetching certificate for {url}: {e}")
            cert_chain_as_pem_str = []

        # print(cert_counter)
        dict_cert = {
            "host" : url,
            "cert" : cert_chain_as_pem_str
        }
        url_cert_mapping.append(dict_cert)
        cert_counter += 1

        if cert_counter >= max_certs_per_batch:
            json_filename = os.path.join(output_directory, f"cert_mapping_{timestamp}_{start_index}.json")
            create_cert_mapping_json(url_cert_mapping, json_filename)

            url_cert_mapping = []
            cert_counter = 0
            start_index += max_certs_per_batch

    if cert_counter > 0:
        json_filename = os.path.join(output_directory, f"cert_mapping_{timestamp}_{start_index}.json")
        create_cert_mapping_json(url_cert_mapping, json_filename)


if __name__ == "__main__":

    url_list_filename = "input\\top-1m.csv"
    with open(url_list_filename, 'r') as url_file:
        url_list = [line.strip().split(',')[1] for line in url_file.readlines()]

    start = 0
    end = 100000
    group_size = 10000
    url_list = url_list[start:end]

    start_time = datetime.now()
    with ProcessPoolExecutor(max_workers=10) as executor:

        futures : list[Future] = []
        while start < end:
            futures.append(executor.submit(concurrentScanner, url_list[start:start+group_size], start))
            start += group_size

        results = [future.result() for future in futures]

    end_time = datetime.now()
    execution_time = end_time - start_time
    my_logger.dumpLog(INFO, f"Execution time for {end - start} certificates: {execution_time.total_seconds()}")
    print("All certificates processed.")










if __name__ == "__main__":

