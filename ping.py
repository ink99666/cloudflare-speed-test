import os
import json
import requests
import threading
import queue
import time
import csv
import ipaddress
import socket
import urllib3
import random
import ping3  # 使用ping3库进行ICMP Ping测试
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException
from aliyunsdkalidns.request.v20150109 import (
    DescribeDomainRecordsRequest,
    DeleteDomainRecordRequest,
    AddDomainRecordRequest
)

# 禁用SSL警告
urllib3.disable_warnings(InsecureRequestWarning)

# ================ 配置参数 ================
# 测试相关配置
TEST_URL_CONTENT = "http://speed.025831.icu/yz.txt"  # 用于内容验证的URL
TEST_URL_SPEED = "http://speed.025831.icu/test3"  # 用于速度测试的URL
#公益测速链接，随时不可用
EXPECTED_CONTENT = "982713813313131"  # 期望从内容验证URL返回的字符串

# 线程控制参数
THREADS_HTTP = 1000  # HTTP内容验证的并发线程数
THREADS_PING = 100  # Ping测试的并发线程数
THREADS_SPEED = 10  # 速度测试的并发线程数

# 文件路径配置
INPUT_FILE = "ip.txt"  # 输入文件，包含CIDR格式的IP段
SPEED_OUTPUT_FILE = "out_speed.csv"  # 速度测试结果输出文件
TOP_IPS_FILE = "top_ips.txt"  # 保存最优IP的文件

# 超时和限制参数
HTTP_TIMEOUT = 3  # HTTP请求超时时间（秒）
PING_COUNT = 4  # 每个IP的Ping次数
PING_TIMEOUT = 1  # Ping超时时间（秒）
MAX_DOWNLOAD_TIME = 5  # 每个IP的最大下载测试时间（秒）
CHUNK_SIZE = 4096  # 下载数据块大小（字节）
MAX_PING_FOR_SPEED_TEST = 160  # 只对延迟低于此值的IP进行速度测试（毫秒）
TOP_IPS_COUNT = 15  # 选择速度最快的IP数量
IP_PER_CIDR = 250  # 从每个CIDR段中抽取的IP数量

# 阿里云DNS配置
ACCESS_KEY_ID = ""  # 阿里云AccessKey ID
ACCESS_KEY_SECRET = ""  # 阿里云AccessKey Secret
DOMAIN = "domain.com"  # 用作DNS更新的主域名
SUB_DOMAIN = "cf"  # 用作DNS更新的子域名前缀
TTL = 600  # DNS记录的TTL值（秒）


# ================ 功能函数 ================
def expand_cidr(cidr, sample_size=IP_PER_CIDR):
    """将CIDR格式的IP段扩展为单个IP列表，并随机抽取指定数量的IP"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # 获取所有主机IP
        all_ips = [str(ip) for ip in network.hosts()]

        # 如果CIDR中的IP数量少于采样数量，则返回所有IP
        if len(all_ips) <= sample_size:
            return all_ips

        # 随机抽取指定数量的IP
        return random.sample(all_ips, sample_size)
    except ValueError:
        return []


def test_ip_content(ip):
    """测试单个IP是否返回预期内容"""
    headers = {'Host': 'speed.025831.icu'}
    try:
        response = requests.get(
            f"http://{ip}/yz.txt",
            headers=headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False
        )
        if response.status_code == 200 and response.text.strip() == EXPECTED_CONTENT:
            return ip
    except:
        pass
    return None


def ping_ip(ip):
    """使用ping3库测试IP的响应时间（毫秒）"""
    total_delay = 0.0
    success_count = 0

    for _ in range(PING_COUNT):
        try:
            # 使用ping3库进行ICMP Ping测试
            delay = ping3.ping(ip, timeout=PING_TIMEOUT, unit='ms')
            if delay is not None and delay > 0:
                total_delay += delay
                success_count += 1
        except:
            # 忽略所有异常，继续下一次尝试
            continue

    # 如果有成功的响应，计算平均延迟
    if success_count > 0:
        avg_delay = total_delay / success_count
        return round(avg_delay, 2)
    return None


def test_speed(ip):
    """测试单个IP的下载速度"""
    headers = {'Host': 'speed.025831.icu'}
    downloaded_bytes = 0
    start_time = time.time()
    end_time = start_time + MAX_DOWNLOAD_TIME
    speed = 0.0

    try:
        response = requests.get(
            TEST_URL_SPEED,
            headers=headers,
            stream=True,
            timeout=MAX_DOWNLOAD_TIME,
            verify=False
        )
        response.raise_for_status()

        # 流式下载数据
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if time.time() > end_time or not chunk:
                break
            downloaded_bytes += len(chunk)

        # 计算速度 (MB/s)
        duration = time.time() - start_time
        if duration > 0:
            speed = downloaded_bytes / duration / 1_048_576  # 字节转MB
    except:
        pass

    return (ip, round(speed, 2))


def get_existing_records(client):
    """获取现有的A记录"""
    try:
        request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
        request.set_DomainName(DOMAIN)
        request.set_Type("A")  # 只查询A记录
        request.set_accept_format('json')

        response = client.do_action_with_exception(request)
        response_data = json.loads(response.decode('utf-8'))

        # 过滤出指定子域名的记录
        records = []
        if 'DomainRecords' in response_data and 'Record' in response_data['DomainRecords']:
            for record in response_data['DomainRecords']['Record']:
                if record.get('RR') == SUB_DOMAIN:
                    records.append(record)

        print(f"找到 {len(records)} 条现有的A记录")
        return records
    except Exception as e:
        print(f"获取现有记录失败: {e}")
        return []


def delete_records(client, records):
    """删除指定的记录"""
    if not records:
        print("没有需要删除的记录")
        return

    print(f"开始删除 {len(records)} 条旧记录...")
    for record in records:
        try:
            record_id = record.get('RecordId')
            if not record_id:
                continue

            request = DeleteDomainRecordRequest.DeleteDomainRecordRequest()
            request.set_RecordId(record_id)
            client.do_action_with_exception(request)
            print(f"已删除记录: {SUB_DOMAIN}.{DOMAIN} -> {record.get('Value', '')} (ID: {record_id})")
        except Exception as e:
            print(f"删除记录失败 (ID: {record_id}): {e}")


def add_records(client, ips):
    """添加新的记录"""
    if not ips:
        print("没有需要添加的新记录")
        return

    print(f"开始添加 {len(ips)} 条新记录...")
    for ip in ips:
        try:
            request = AddDomainRecordRequest.AddDomainRecordRequest()
            request.set_DomainName(DOMAIN)
            request.set_RR(SUB_DOMAIN)
            request.set_Type("A")
            request.set_Value(ip)
            request.set_TTL(TTL)

            response = client.do_action_with_exception(request)
            response_data = json.loads(response.decode('utf-8'))
            record_id = response_data.get('RecordId', '未知ID')
            print(f"已添加记录: {SUB_DOMAIN}.{DOMAIN} -> {ip} (记录ID: {record_id})")
        except ServerException as e:
            if e.error_code == "DomainRecordDuplicate":
                print(f"记录已存在，跳过添加: {ip} (错误信息: {e.message})")
            else:
                print(f"添加记录失败 ({ip}): 错误代码: {e.error_code}, 错误信息: {e.message}")
        except Exception as e:
            print(f"添加记录失败 ({ip}): {e}")


def update_dns_records(ips):
    """更新DNS记录"""
    try:
        # 初始化客户端
        client = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET)

        # 步骤1: 获取现有记录
        existing_records = get_existing_records(client)

        # 步骤2: 删除现有记录
        delete_records(client, existing_records)

        # 步骤3: 添加新记录
        add_records(client, ips)

        print("DNS记录更新完成!")

    except ClientException as e:
        print(f"阿里云客户端错误: 错误代码: {e.error_code}, 错误信息: {e.message}")
    except ServerException as e:
        print(f"阿里云服务器错误: 错误代码: {e.error_code}, 错误信息: {e.message}")
    except Exception as e:
        print(f"发生未知错误: {e}")


# ================ 主流程 ================
def main():
    # 第一阶段：HTTP内容验证
    print("=" * 50)
    print("开始解析CIDR地址段并随机抽样...")
    all_ips = []
    try:
        with open(INPUT_FILE, 'r') as f:
            for cidr in f:
                cidr = cidr.strip()
                if cidr:
                    # 从每个CIDR中随机抽取25个IP
                    ips_from_cidr = expand_cidr(cidr, IP_PER_CIDR)
                    all_ips.extend(ips_from_cidr)
                    print(f"从 {cidr} 中抽取了 {len(ips_from_cidr)} 个IP")
    except FileNotFoundError:
        print(f"错误：文件 {INPUT_FILE} 不存在")
        return

    if not all_ips:
        print("未找到有效的IP地址")
        return

    total_ips = len(all_ips)
    print(f"已抽取 {total_ips} 个IP地址，开始HTTP内容验证...")

    # HTTP内容验证
    valid_ips = []
    processed_count = 0
    last_update_time = time.time()
    start_time = time.time()

    # 使用队列管理任务
    ip_queue = queue.Queue()
    for ip in all_ips:
        ip_queue.put(ip)

    def worker():
        nonlocal processed_count, valid_ips
        while not ip_queue.empty():
            try:
                ip = ip_queue.get_nowait()
                if result := test_ip_content(ip):
                    valid_ips.append(result)
            finally:
                with threading.Lock():
                    processed_count += 1
                ip_queue.task_done()

    # 创建并启动线程
    threads = []
    for _ in range(THREADS_HTTP):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # 显示进度
    while processed_count < total_ips:
        time.sleep(0.5)
        current_time = time.time()

        # 每处理1000个IP或每5秒更新一次进度
        if processed_count % 1000 == 0 or current_time - last_update_time >= 5:
            elapsed_time = current_time - start_time
            processed_per_sec = processed_count / elapsed_time if elapsed_time > 0 else 0
            remaining_time = (total_ips - processed_count) / processed_per_sec if processed_per_sec > 0 else 0

            # 格式化显示时间
            elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            remaining_str = time.strftime("%H:%M:%S", time.gmtime(remaining_time))

            print(f"\rHTTP内容验证进度: {processed_count}/{total_ips} | "
                  f"有效IP: {len(valid_ips)} | "
                  f"已用时间: {elapsed_str} | "
                  f"预计剩余: {remaining_str} | "
                  f"速度: {processed_per_sec:.1f} IP/s", end='', flush=True)
            last_update_time = current_time

    # 等待所有线程完成
    ip_queue.join()

    print(f"\nHTTP内容验证完成！找到 {len(valid_ips)} 个有效IP")

    if not valid_ips:
        print("没有找到符合条件的IP")
        return

    # 第二阶段：Ping测试
    print("=" * 50)
    print("开始Ping测试...")
    ping_results = []
    processed_count = 0
    last_update_time = time.time()
    start_time = time.time()

    # 使用队列管理任务
    ip_queue = queue.Queue()
    for ip in valid_ips:
        ip_queue.put(ip)

    def ping_worker():
        nonlocal processed_count, ping_results
        while not ip_queue.empty():
            try:
                ip = ip_queue.get_nowait()
                if ping_time := ping_ip(ip):
                    ping_results.append((ip, ping_time))
            finally:
                with threading.Lock():
                    processed_count += 1
                ip_queue.task_done()

    # 创建并启动线程
    threads = []
    for _ in range(THREADS_PING):
        t = threading.Thread(target=ping_worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # 显示进度
    while processed_count < len(valid_ips):
        time.sleep(0.5)
        current_time = time.time()

        # 每处理100个IP或每5秒更新一次进度
        if processed_count % 100 == 0 or current_time - last_update_time >= 5:
            elapsed_time = current_time - start_time
            processed_per_sec = processed_count / elapsed_time if elapsed_time > 0 else 0
            remaining_time = (len(valid_ips) - processed_count) / processed_per_sec if processed_per_sec > 0 else 0

            # 格式化显示时间
            elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            remaining_str = time.strftime("%H:%M:%S", time.gmtime(remaining_time))

            print(f"\rPing测试进度: {processed_count}/{len(valid_ips)} | "
                  f"有效结果: {len(ping_results)} | "
                  f"已用时间: {elapsed_str} | "
                  f"预计剩余: {remaining_str} | "
                  f"速度: {processed_per_sec:.1f} IP/s", end='', flush=True)
            last_update_time = current_time

    # 等待所有线程完成
    ip_queue.join()

    # 按延迟排序
    ping_results.sort(key=lambda x: x[1])

    # 筛选低延迟IP
    low_latency_ips = [ip for ip, latency in ping_results if latency <= MAX_PING_FOR_SPEED_TEST]

    if not low_latency_ips:
        print(f"\n没有找到延迟低于{MAX_PING_FOR_SPEED_TEST}ms的IP")
        return

    print(f"\n找到 {len(low_latency_ips)} 个延迟低于{MAX_PING_FOR_SPEED_TEST}ms的IP")

    # 第三阶段：速度测试
    print("=" * 50)
    print("开始速度测试...")
    speed_results = []
    processed_count = 0
    last_update_time = time.time()
    start_time = time.time()

    # 使用线程池管理速度测试任务
    with ThreadPoolExecutor(max_workers=THREADS_SPEED) as executor:
        futures = {executor.submit(test_speed, ip): ip for ip in low_latency_ips}

        for i, future in enumerate(as_completed(futures)):
            ip = futures[future]
            try:
                if result := future.result():
                    # 查找对应的Ping延迟
                    ping = next((p for ip_p, p in ping_results if ip_p == ip), None)
                    if ping:
                        speed_results.append((ip, ping, result[1]))
            except:
                pass

            processed_count = i + 1
            current_time = time.time()

            # 每处理1个IP或每5秒更新一次进度
            if processed_count % 1 == 0 or current_time - last_update_time >= 5:
                elapsed_time = current_time - start_time
                processed_per_sec = processed_count / elapsed_time if elapsed_time > 0 else 0
                remaining_time = (
                                         len(low_latency_ips) - processed_count) / processed_per_sec if processed_per_sec > 0 else 0

                # 格式化显示时间
                elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
                remaining_str = time.strftime("%H:%M:%S", time.gmtime(remaining_time))

                print(f"\r速度测试进度: {processed_count}/{len(low_latency_ips)} | "
                      f"已用时间: {elapsed_str} | "
                      f"预计剩余: {remaining_str} | "
                      f"速度: {processed_per_sec:.1f} IP/s", end='', flush=True)
                last_update_time = current_time

    # 按速度排序
    speed_results.sort(key=lambda x: x[2], reverse=True)

    # 保存速度结果
    with open(SPEED_OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP地址', 'Ping延迟(ms)', '下载速度(MB/s)'])
        writer.writerows(speed_results)

    # 统计有效结果
    valid_speed_results = [r for r in speed_results if r[2] > 0]

    print(f"\n速度测试完成！结果已保存到 {SPEED_OUTPUT_FILE}")
    if valid_speed_results:
        print(f"有效IP数量: {len(valid_speed_results)}/{len(low_latency_ips)}")
        print(f"最快IP: {speed_results[0][0]} - Ping: {speed_results[0][1]}ms, 速度: {speed_results[0][2]} MB/s")

        # 选择最快的30个IP
        top_ips = [ip for ip, ping, speed in speed_results[:TOP_IPS_COUNT]]

        # 保存到文件
        with open(TOP_IPS_FILE, 'w') as f:
            for ip in top_ips:
                f.write(f"{ip}\n")
        print(f"已保存最快的 {len(top_ips)} 个IP到 {TOP_IPS_FILE}")

        # 第四阶段：更新DNS记录
        print("=" * 50)
        print(f"开始更新DNS记录: {SUB_DOMAIN}.{DOMAIN}")
        update_dns_records(top_ips)
    else:
        print("没有获得有效的速度测试结果")


if __name__ == "__main__":
    start_time = time.time()
    main()
    duration = time.time() - start_time
    print(f"脚本总运行时间: {duration // 60:.0f}分 {duration % 60:.0f}秒")