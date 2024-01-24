from tkinter import CASCADE
from django.http import HttpResponse
from django.shortcuts import render
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import re
import time

import csv
import os
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
import datetime
from tqdm import tqdm

#initial
def index(request):
    return render(request, 'index.html')

#process
global processed
processed = 0
def get_subject_alternative_names(cert):
    try:
        san = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        return ", ".join([str(name) for name in san.value])
    except x509.ExtensionNotFound:
        return None
def get_extension_values(cert, extension_oid):
    try:
        extension = cert.extensions.get_extension_for_oid(extension_oid)
        return str(extension.value)
    except x509.ExtensionNotFound:
        return None
def get_key_length(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.key_size
    return None
def get_ca_country(issuer):
    for attribute in issuer:
        if attribute.oid == x509.NameOID.COUNTRY_NAME:
            return attribute.value
    return None
def process():
    global processed
    if(processed != 0):
        return
    processed +=1
    cert_folder = 'certificates'
    output_csv = 'certificates_info.csv'
    cert_files = [f for f in os.listdir(cert_folder) if f.endswith('.pem')]

    headers = ['Domain', 'Serial Number', 'Signature Algorithm', 'Version', 'Issuer', 
            'Subject', 'Not Before', 'Not After', 'Key Length', 'CA Country', 
            'Subject Alternative Names', 'Basic Constraints', 'Key Usage', 
            'Extended Key Usage', 'Time Valid']

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(headers)

        for filename in tqdm(cert_files, desc="Processing Certificates"):
            if filename.endswith('.pem'):
                domain = filename.replace('.pem', '')
                file_path = os.path.join(cert_folder, filename)

                with open(file_path, 'rb') as file:
                    cert_data = file.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                    serial_number = format(cert.serial_number, 'x') #序列号
                    public_key = cert.public_key()  #公钥
                    signature_algorithm = cert.signature_hash_algorithm.name    #签名算法
                    version = cert.version.name #版本号
                    issuer = cert.issuer.rfc4514_string()   #发行者信息
                    subject = cert.subject.rfc4514_string() #持有者信息
                    not_before = cert.not_valid_before  #有效期起始时间
                    not_after = cert.not_valid_after    #有效期终止时间
                    key_length = get_key_length(public_key)   #密钥长度
                    ca_country = get_ca_country(cert.issuer)    #发行者国家
                    sans = get_subject_alternative_names(cert)
                    basic_constraints = get_extension_values(cert, x509.OID_BASIC_CONSTRAINTS)
                    key_usage = get_extension_values(cert, x509.OID_KEY_USAGE)
                    extended_key_usage = get_extension_values(cert, x509.OID_EXTENDED_KEY_USAGE)

                    #证书合规性检查
                    time_valid = (not_before <= datetime.datetime.now() and 
                                datetime.datetime.now() <= not_after)   #当前时间是否有效

                    csvwriter.writerow([domain, serial_number, signature_algorithm, version, issuer, 
                                        subject, not_before, not_after, key_length, ca_country, 
                                        sans, basic_constraints, key_usage, extended_key_usage, time_valid])
def extractInfo(subject):
    toFind = ['CN', 'O', 'OU', 'C', 'S', 'L']
    info = {}
    for key in toFind:
        temp = r"%s"%subject
        temp = temp.replace('\\,', 'A magic string that can not come up @ all')
        info[key] = re.search(f'{key}=(.*?),', temp)
        if info[key] is not None:
            info[key] = info[key].group(1).replace('A magic string that can not come up @ all', ',')
        else:
            info[key] = '-'
    return info

#certificate
def cert(request, page):
    process()
    data = pd.read_csv('certificates_info.csv', sep=',', usecols=['Domain', 'Signature Algorithm', 'Issuer', 'Subject', 'Key Length', 'Time Valid'])
    data = data.values
    valid = np.sum(data[:, 5])
    context = {}
    algs = {}
    for sa in data[:, 1]:
        if algs.__contains__(sa):
            algs[sa] += 1
        else:
            algs[sa] = 1
    
    algs = sorted(algs.items(), key=lambda x:x[1], reverse=True)
    context["algs"] = []
    for v in algs:
        context["algs"].append({"name": v[0], "num": f"{v[1] / len(data) * 100:.3f}%"})

    context['datasize'] = len(data)
    context['expired'] = f"{(1 - valid / len(data)) * 100:.3f}%"
    context["avgKeyLen"] = np.mean(data[:, 4])

    limit = 20
    if page is None:
        page = 0
    page = int(page)
    pageLimit = len(data) // limit - 1
    context['prevPage'] = page - 1 if page > 0 else 0
    context['nextPage'] = page + 1 if page < pageLimit else pageLimit
    context['lastPage'] = pageLimit
    context['data'] = []
    for i in range(limit):
        if page * limit + i == len(data):
            break
        issuer = extractInfo(data[page * limit + i, 2])
        subject = extractInfo(data[page * limit + i, 3])
        print(subject["CN"])
        context['data'].append({
            "domain": data[page * limit + i, 0],
            "signature": data[page * limit + i, 1],
            "issuerCN": issuer['CN'],
            "issuerO": issuer['O'],
            "issuerOU": issuer['OU'],
            "issuerC": issuer['C'],
            "issuerS": issuer['S'],
            "issuerL": issuer['L'],
            "subjectCN": subject['CN'],
            "subjectO": subject['O'],
            "subjectOU": subject['OU'],
            "subjectC": subject['C'],
            "subjectS": subject['S'],
            "subjectL": subject['L'],
            "keyLength": data[page * limit + i, 4],
            "timeValid": data[page * limit + i, 5],
        })
    return render(request, 'cert.html', context)

#fail cert
def plot():
    type_pair={}
    with open('cer_ver_fail_type.csv',newline='', encoding='utf-8') as dataFile:
        reader = csv.reader(dataFile)
        for row in reader:
            type_pair[row[0]] = row[1]
    trans = {}
    k = type_pair.keys()
    keys=list(k)
    print(type(keys))
    trans[keys[0]] = '无法获得本地\n颁发者证书'
    trans[keys[1]] = '证书链中存在\n自签发证书'
    trans[keys[2]] = '主机名不匹配'
    trans[keys[3]] = '证书已失效'
    trans[keys[4]] = '自签发证书'
    trans[keys[5]] = '弱密码'
    trans[keys[6]] = 'CA签名算法弱'
    x = [trans[keys[i]] for i in range(len(keys))]
    v = type_pair.values()
    values = list(v)
    for i in range(len(values)):
        values[i] = int(values[i])

    plt.rcParams["font.sans-serif"] = ["SimHei"]
    plt.rcParams['figure.figsize'] = (8,4)
    plt.barh(x, width = values)
    plt.xlabel("数量")
    plt.title("存在问题的证书统计")
    plt.savefig('figure1.png')
def cert_fail(request, page):
    plot()
    error_type = []
    with open ('cert_ver_file_info.csv', newline='', encoding='utf-8') as dataFile:
        reader = csv.reader(dataFile)
        for row in reader:
            error_type.append({
                "name": row[0],
                "type": row[1]
            })
    context = {}
    context["datasize"] = len(error_type)

    limit = 10
    if page is None:
        page = 0
    page = int(page)
    pageLimit = len(error_type) // limit 
    if(len(error_type)%limit == 0):
        pageLimit -= 1

    context['prevPage'] = page - 1 if page > 0 else 0
    context['nextPage'] = page + 1 if page < pageLimit else pageLimit
    context['lastPage'] = pageLimit

    context['data'] = []
    for i in range(limit):
        if page * limit + i == len(error_type):
            break
        domain = error_type[page * limit + i]
        context['data'].append({
            "name": domain["name"],
            "type": domain["type"]
        })
    return render(request, 'cert_fail.html', context)

#CA info
def ca(request, page):
    data = pd.read_csv('certificates_info.csv', sep=',', usecols=['Domain', 'Signature Algorithm', 'Issuer', 'Subject', 'CA Country', 'Time Valid', ])
    data = data.values

    cas = {}
    for i in range(data.shape[0]):
        caData = extractInfo(data[i, 2])
        caData["R"] = "False"
        caData["C"] = data[i,4]

        if cas.__contains__(caData["O"]):
            cas[caData["O"]]["number"] += 1
            if(data[i,2] == data[i,3]):
                cas[caData["O"]]["root"] = "True"
        else:
            cas[caData["O"]] = {
                "name": caData["CN"],
                "number": 1,
                "country": caData["C"],
                "location": caData["L"],
                "organization": caData["O"],
                "state": caData["S"],
                "valid": 0,
                "algs": {},
                "root": caData["R"]
            }

        if data[i, 5]:
            cas[caData["O"]]["valid"] += 1

        if cas[caData["O"]]["algs"].__contains__(data[i, 1]):
            cas[caData["O"]]["algs"][data[i, 1]] += 1
        else:
            cas[caData["O"]]["algs"][data[i, 1]] = 1

    cas = sorted(list(cas.values()), key=lambda x:x["number"], reverse=True)
    for ca in cas:
        ca["algs"] = sorted(ca["algs"].items(), key=lambda x:x[1], reverse=True)[0][0]
    
    context = {}
    context["datasize"] = len(cas)

    limit = 10
    if page is None:
        page = 0
    page = int(page)
    pageLimit = len(cas) // limit 
    if(len(cas)%limit == 0):
        pageLimit -= 1

    context['prevPage'] = page - 1 if page > 0 else 0
    context['nextPage'] = page + 1 if page < pageLimit else pageLimit
    context['lastPage'] = pageLimit

    context['data'] = []
    for i in range(limit):
        if page * limit + i == len(cas):
            break
        ca = cas[page * limit + i]
        context['data'].append({
            "name": ca["name"],
            "number": ca["number"],
            "organization": ca["organization"],
            "country": ca["country"],
            "state": ca["state"],
            "location": ca["location"],
            "valid": ca["valid"] / ca["number"],
            "alg": ca["algs"],
            "root": ca["root"]
        })

    return render(request, 'ca.html', context)

#crawl
global error_num
global error_verfail_num
global cert_num
error_num = 0
error_verfail_num = 0
cert_num = 0
def save_certificate_pem(domain, output_dir, error_log, cert_ver_fail_log, save_pair):
    global error_num
    global error_verfail_num
    global cert_num
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.settimeout(5)
        try:
            cert_num += 1
            s.connect((domain, 443))
            cert_bin = s.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            with open(os.path.join(output_dir, f"{domain}.pem"), "w") as cert_file:
                cert_file.write(cert_pem)
        except Exception as e:
            cert_num -= 1
            error_num += 1
            error_message = str(e)
            if (error_message.startswith('[SSL: CERTIFICATE_VERIFY_FAILED]')):
                if(error_message.startswith('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch,')):
                    if('Hostname mismatch' in save_pair):
                        save_pair['Hostname mismatch'] += 1
                    else:
                        save_pair['Hostname mismatch'] = 1
                else:
                    if(error_message in save_pair):
                        save_pair[error_message] += 1
                    else:
                        save_pair[error_message] = 1
                error_verfail_num += 1
                cert_num += 1
                with open(cert_ver_fail_log, "a", newline='') as cert_ver_fail_file:
                    certverfail_writer = csv.writer(cert_ver_fail_file)
                    certverfail_writer.writerow([domain, error_message])
            print(f"Error retrieving certificate for {domain}: {error_message}")
            with open(error_log, "a", newline='') as error_file:
                error_writer = csv.writer(error_file)
                error_writer.writerow([domain, error_message])
            print(error_num,' ',error_verfail_num,' ',cert_num)
def process_certificates(file_path, output_dir, log_file, error_log, cert_ver_fail_log):
    start_time = time.time()
    verifail_info = {}
    num_old = 0
    with open(file_path, newline='', encoding='utf-8') as csvfile, open(log_file, "a") as logfile:
        reader = csv.reader(csvfile)
        next(reader)
        for row in reader:
            print(reader.line_num)
            if (reader.line_num <= num_old):
                break
            num_old = reader.line_num
            domain = row[1]
            save_certificate_pem(domain, output_dir, error_log, cert_ver_fail_log, verifail_info)
            if reader.line_num % 100 == 0:
                elapsed_time = time.time() - start_time
                logfile.write(f"Processed {reader.line_num} domains in {elapsed_time:.2f} seconds\n")
                print(f"Processed {reader.line_num} domains in {elapsed_time:.2f} seconds")
            if cert_num >= 100000:
                break
    with open('cert_veri_fail_type.csv', "a", newline='') as save_file:
        save_writer = csv.writer(save_file)
        for key, value in verifail_info.items():
            save_writer.writerow([key,value])
def crawler():
    output_dir = 'certificates'
    os.makedirs(output_dir, exist_ok=True)
    log_file = 'process_log.txt'
    error_log = 'error_info.csv'
    cert_ver_fail_log = 'cert_ver_file_info.csv'
    process_certificates('top10milliondomains.csv', output_dir, log_file, error_log,cert_ver_fail_log)
def crawl(request):
    crawler()
    return render(request, 'crawl.html')
