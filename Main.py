import binascii
import os
import pickle
import socket
import threading
import time
import re

dns_servers = ["208.67.222.222", "208.67.220.220", "8.8.8.8", "8.8.4.4", "84.200.69.80"]

headline_format_error = b"\x81\x81\x00\x01\x00\x00\x00\x00\x00\x00"
headline_not_exist = b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
headline_not_implmented = b"\x81\x84\x00\x01\x00\x00\x00\x00\x00\x00"
headline_server_error = b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00"
response_for_requset_to_server_name = b"\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00%s\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x80\x00 \x05Pavel\x08Kononsky\x02ru\x00"

domain_ip = dict()
domain_ipv6 = dict()
domain_ns = dict()
ip_domain = dict()

type_dicts = {b"\x00\x01": domain_ip, b"\x00\x02": domain_ns, b"\x00\x1c": domain_ipv6, b"\x00\x0c": ip_domain}


def check_and_delete_ttl_off_records():
    while True:
        time.sleep(5)
        for dict in [domain_ip, domain_ipv6, domain_ns, ip_domain]:
            records_to_delete = set()
            for domain, data in dict.items():
                if len(data) == 0:
                    records_to_delete.add(domain)
                    continue
                for _, ttl, record_time in dict[domain]:
                    result = ""
                    for t in ttl:
                        hex_f = hex(t)[2:]
                        hex_f = (8 - len(hex_f)) * "0" + hex_f
                        result += bin(int(hex_f, 16))[2:]
                    ttl = int(result, 2)
                    time_now = round(time.time())
                    if time_now - ttl > record_time:
                        records_to_delete.add(domain)
            for domain in records_to_delete:
                dict.pop(domain)


def off_server_waiter():
    input("press enter to off server\n")
    serialize()
    os.abort()


def serialize():
    pickle.dump(domain_ip, open("server_data\domain_ip", mode="bw"))
    pickle.dump(domain_ipv6, open("server_data\domain_ipv6", mode="bw"))
    pickle.dump(domain_ns, open("server_data\domain_ns", mode="bw"))
    pickle.dump(ip_domain, open("server_data\ip_domain", mode="bw"))


def load_dicts():
    global domain_ip, domain_ipv6, domain_ns, ip_domain
    domain_ip = pickle.load(open("server_data\domain_ip", mode="br"))
    domain_ipv6 = pickle.load(open("server_data\domain_ipv6", mode="br"))
    domain_ns = pickle.load(open("server_data\domain_ns", mode="br"))
    ip_domain = pickle.load(open("server_data\ip_domain", mode="br"))
    type_dicts[b"\x00\x01"] = domain_ip
    type_dicts[b"\x00\x02"] = domain_ns
    type_dicts[b"\x00\x1c"] = domain_ipv6
    type_dicts[b"\x00\x0c"] = ip_domain


def check_connection_to_network():
    try:
        sock = socket.socket()
        sock.connect(("google.com", 80))
        sock.close()
        return True
    except:
        return False


def answer_waiter(sock):
    time.sleep(0.5)
    sock.close()


def get_data_from_dns(request, dns):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(request, (dns, 53))
    t = threading.Thread(target=answer_waiter, args=(sock,))
    t.start()
    data, _ = sock.recvfrom(4096)
    sock.close()
    return data


def get_query(data):
    i = 0
    domain = b""
    while data[i] != 0:
        domain += data[i + 1:data[i] + i + 1]
        domain += b"."
        i += data[i] + 1
    return domain[:len(domain) - 1].decode()


def get_useful_data(data):
    #id = data[:2]
    #flags = data[2:4]
    #flags_first_byte = bin(int(hex(flags[0])[2:]))[2:]
    #flags_first_byte = (8 - len(flags_first_byte)) * "0" + flags_first_byte
    #flags_second_byte = bin(int(hex(flags[1])[2:]))[2:]
    #flags_second_byte = (8 - len(flags_second_byte)) * "0" + flags_second_byte
    # QR = flags_first_byte[0]  # запрос - 0 ответ - 1
    # Opcode = flags_first_byte[1:5]  # тип запроса
    # AA = flags_first_byte[5]  # авторитетный ответ 1 - Да 0 - Нет
    # TC = flags_first_byte[6]
    # RD = flags_first_byte[7]  # установленная рекурсия
    # RA = flags_second_byte[0]  # показывает поддерживает ли сервер рекурсивный запрос
    # Z = flags_second_byte[1:5]  # зарезервированно
    # RCODE = flags_second_byte[5:]  # код ответа (0 - без ошибок, 1 - format error, ...)

    # QDCOUNT = data[4:6]  # кол-во вопросов
    # ANCOUNT = data[6:8]  # кол-во ресурсных записей в ответе
    # NSCOUNT = data[8:10]  # кол-во имен NS
    # ARCOUNT = data[10:12]  # кол-во ресурсных записей в доп секции
    # request = data[12:data.find(b"\xc0\x0c")]
    # query = get_query(data[12:])
    answer = data[data.find(b"\xc0\x0c"):]

    offset = 0
    while offset != len(answer):
        NAME = answer[offset: offset + 2]
        name = get_true_name(data[get_offset(NAME):], data)

        TYPE = answer[offset + 2: offset + 4]
        CLASS = answer[offset + 4:offset + 6]
        TTL = answer[offset + 6: offset + 10]
        RDLENGHT = answer[offset + 10: offset + 12]
        rdlenght = get_int_data_from_bytes(RDLENGHT)
        RDATA = answer[offset + 12:rdlenght + 12 + offset]
        # A
        if TYPE == b"\x00\x01":
            if domain_ip.get(name) is None:
                domain_ip[name] = list()
            domain_ip[name].append((RDATA, TTL, round(time.time())))
            type_dicts[TYPE] = domain_ip
        # NS
        if TYPE == b"\x00\x02":
            ns = get_true_name(answer[offset + 12:], data)
            if domain_ns.get(name) is None:
                domain_ns[name] = list()
            domain_ns[name].append((ns, TTL, round(time.time())))
            type_dicts[TYPE] = domain_ns
        # AAAA
        if TYPE == b"\x00\x1c":
            if domain_ipv6.get(name) is None:
                domain_ipv6[name] = list()
            domain_ipv6[name].append((RDATA, TTL, round(time.time())))
            type_dicts[TYPE] = domain_ipv6
        # PTR
        if TYPE == b"\x00\x0c":
            if ip_domain.get(name) is None:
                ip_domain[name] = list()
            ip_domain[name].append((RDATA, TTL, round(time.time())))
            type_dicts[TYPE] = ip_domain

        offset += 12 + rdlenght


def get_int_data_from_bytes(data):
    result = ""
    for i in range(len(data)):
        hex_d = hex(data[i])[2:]
        hex_d = (2 - len(hex_d)) * "0" + hex_d
        result += bin(int(hex_d, 16))[2:]
    return int(result, 2)


def get_offset(data):
    offset_first_byte = bin(int(hex(data[0])[2:], 16))[2:]
    hex_second_byte = hex(data[1])[2:]
    hex_second_byte = (2 - len(hex_second_byte)) * "0" + hex_second_byte
    offset_second_byte = bin(int(hex_second_byte, 16))[2:]
    offset_second_byte = (8 - len(offset_second_byte)) * "0" + offset_second_byte
    offset = offset_first_byte + offset_second_byte
    offset = offset[2:]  # первые два байта всегда 1 и не относятся к смещению
    return int(offset, 2)


def get_true_name(data, data_all):
    i = 0
    result = b""
    while data[i] != 0:
        if data[i] == b"\xc0"[0]:
            result += get_true_name(data_all[get_offset(data[i:i + 2]):], data_all)
            break
        else:
            count = data[i]
            result += data[i + 1: i + count + 1]
            result += b"."
            i += count + 1
    if result[len(result) - 1] == b"."[0]:
        return result[:len(result) - 1]
    return result


def get_answer(data, query, req_type):
    dict = type_dicts[req_type]
    if dict.get(query.encode()) is None:
        dict[query.encode()] = list()
    answer = b""
    answer += data[:2]
    answer += b"\x81\x80\x00\x01"  # тип - ответ, не достоверный ответ, без ошибок, 1 вопрос
    hex_l = hex(len(dict[query.encode()]))[2:]
    hex_l = (4 - len(hex_l)) * "0" + hex_l
    answer += binascii.unhexlify(hex_l)  # количество ответов
    answer += b"\x00\x00\x00\x00"  # доп информация
    answer += data[12:]

    for i, ttl, _ in dict[query.encode()]:
        answer += b"\xc0\x0c"
        answer += req_type
        answer += b"\x00\x01"
        answer += ttl

        if req_type == b"\x00\x02":
            hex_l = hex(len(i) + 2)[2:]
            hex_l = (4 - len(hex_l)) * "0" + hex_l
            answer += binascii.unhexlify(hex_l)
            for j in i.split(b"."):
                str_len = hex(len(j))[2:]
                if len(str_len) % 2 == 1:
                    str_len = "0" + str_len
                answer += binascii.unhexlify(str_len)
                answer += j
            answer += b"\x00"
        else:
            hex_l = hex(len(i))[2:]
            hex_l = (4 - len(hex_l)) * "0" + hex_l
            answer += binascii.unhexlify(hex_l)
            answer += i

    return answer

def check_query_exist(query):
    try:
        sock2 = socket.socket()
        sock2.connect((query, 80))
        sock2.close()
        return True
    except:
        return False

def check_address_to_correct(address):
    address = address.split(".")
    if len(address) == 4:
        for i in address:
            if int(i) < 0 or int(i) > 255:
                return False
    return True

if __name__ == '__main__':
    if not check_connection_to_network():
        print("Нет подключения к интернету")
        os.abort()

    try:
        load_dicts()
    except:
        pass

    t1 = threading.Thread(target=check_and_delete_ttl_off_records)
    t1.start()

    t2 = threading.Thread(target=off_server_waiter)
    t2.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 53))

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            id = data[:2]
            query = get_query(data[12:])
            req_type = data[len(data) - 4: len(data) - 2]
            if req_type not in type_dicts.keys():
                sock.sendto(id + headline_not_implmented + data[12:], addr)
                continue

            if query == "1.0.0.127.in-addr.arpa":
                sock.sendto((id + response_for_requset_to_server_name) % data[12:], addr)
                continue

            if type_dicts[req_type].get(query.encode()) is not None:
                sock.sendto(get_answer(data, query, req_type), addr)
                continue

            if len(re.findall(r"\d+\.\d+\.\d+\.\d+", query)) != 0:
                if not check_address_to_correct(query):
                    sock.sendto(id + headline_not_exist + data[12:], addr)
                    continue
            else:
                if not check_query_exist(query):
                    sock.sendto(id + headline_not_exist + data[12:], addr)
                    continue

            if domain_ns.get(query) is not None:
                domain_data = get_data_from_dns(f_d, domain_ns[query][0][0])
                get_useful_data(domain_data)
            else:
                #f_d = bytearray(data)
                #f_d[len(data) - 4: len(data) - 2] = b"\x00\xff"
                #f_d = bytes(f_d)
                for dns_server in dns_servers:
                    try:
                        domain_data = get_data_from_dns(data, dns_server)
                        get_useful_data(domain_data)
                    except:
                        pass
                    if type_dicts[req_type].get(query.encode()) is None:
                        continue
                    else:
                        break

            sock.sendto(get_answer(data, query, req_type), addr)


        except:
            raise
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", 53))
            try:
                sock.sendto(id + headline_server_error + data[12:], addr)
            except:
                pass
            pass
