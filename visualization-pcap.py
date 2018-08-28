import pandas as pd
import numpy as np
import dpkt
import seaborn as sns
import matplotlib.pyplot as plt
import math

import time
start_time = time.time()


def get_list_ID(df):
    """Получить список индексов полей сетевых протоколов по байтам.

    Параметры:
    df - DataFrame
        Матрица структуры pcap-файла. Столбцы: word - поле протокола,
                                               start - порядкой номер байта начала,
                                               end - порядкой номер байта конца.
    Выход:
    pkt - array
        Список индексов.
    """
    pkt = list()
    for index, row in df.iterrows():
        d = (row['end'] - row['start']) + 1
        pkt.extend([ row['index'] for i in range(d)])
        # if row['start'] == p:
        #     while (p != row['end'] + 1):
        #         print(p)
        #         pkt.append([p, row['index']])
        #         p = p + 1
        #         if p == max:
        #             break
        # else:
        #     while (p != row['start']):
        #         print(p)
        #         pkt.append([p, np.nan])
        #         p = p + 1
        #         if p == max:
        #             break
        #     while (p != row['end'] + 1):
        #         pkt.append([p, row['index']])
        #         p = p + 1
        #         if p == max:
        #             break
    #ix = pd.DataFrame(pkt)[1].values
    return np.array(pkt)


def parse_packet(pkt, start):
    """Распарсить pcap-файл по полям сетевых протоколов.

    Параметры:
    pkt - list
        Список байтов сетевого пакета.
    start - int
        Указатель на позицию байта.

    Выход:
    dict_pcap - list
        Список полей сетевых протоколов пакета с указателями.
    """
    #dict_pcap = np.array([])
    dict_pcap = list()                                                # Список полей сетевых протоколов.
    endp = start + len(pkt)
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        dict_pcap = [['eth.dst', start, start + 5],
                     ['eth.src', start + 6, start + 11],
                     ['eth.type', start + 12, start + 13]]
        padding = len(pkt) - len(eth)
        if padding:
            dict_pcap.append(['pad', start + len(pkt) - padding, start + len(pkt)-1])
        start = start + dpkt.ethernet.ETH_HDR_LEN
        proto = 0
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp = eth.data
            dict_pcap.extend([['arp.ht', start, start+1],
                              ['arp.p', start+2, start+3],
                              ['arp.hs', start+4, start+4],
                              ['arp.ps', start+5, start+5],
                              ['arp.opcode', start + 6, start + 7],
                              ['arp.sen_mac', start + 8, start + 13],
                              ['arp.sen_ip', start + 14, start + 17],
                              ['arp.tar_mac', start + 18, start + 23],
                              ['arp.ter_ip', start + 24, start + 27]])
            if arp.data:
                dict_pcap.append(['arp.data', start + 28, start + 28 + len(arp.data) - 1])
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            proto = ip.p
            ipdata = ip.data
            dict_pcap.extend([['ip.vhl', start, start],
                              ['ip.dsf', start + 1, start + 1],
                              ['ip.len', start + 2, start + 3],
                              ['ip.id', start + 4, start + 5],
                              ['ip.flags', start + 6, start + 6],
                              ['ip.offset', start + 7, start + 7],
                              ['ip.ttl', start + 8, start + 8],
                              ['ip.p', start + 9, start + 9],
                              ['ip.sum', start + 10, start + 11]])
            start = start + 12
            dict_pcap.extend([['ip.dst', start, start +3],
                              ['ip.src', start + 4, start + 7]])
            start = start + 8
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                dict_pcap.extend([['tcp.dport', start, start + 1],
                                  ['tcp.sport', start + 2, start + 3],
                                  ['tcp.seq', start + 4, start + 7],
                                  ['tcp.ack', start + 8, start + 11],
                                  ['tcp.flags', start + 12, start + 13],
                                  ['tcp.win', start + 14, start + 15],
                                  ['tcp.sum', start + 16, start + 17],
                                  ['tcp.urp', start + 18, start + 19]])
                if tcp.opts:
                    dict_pcap.append(['tcp.opts', start + 20, start + 19 + len(tcp.opts)])
                if ((tcp.dport == 443) or (tcp.sport == 443)) and len(tcp.data) > 0:
                    start = start + 20
                    ssl = tcp.data
                    dict_pcap.append(['ssl', start, start + len(ssl) - 1])
                if (tcp.dport == 80) or (tcp.sport == 80) and len(tcp.data) > 0:
                    start = start + 20
                    http = dpkt.http.Request(tcp.data)
                    methuri = bytes( http.method + ' ' + http.uri + ' ',
                                     encoding = 'utf-8')
                    dict_pcap.append(['http.methuri', start, start + len(methuri) - 1])
                    start = start + len(methuri)
                    host = bytes('HTTP/' + http.version + '\r\n' + 'Host: ' + http.headers['host'],
                                 encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.host', start, start + len(host)-1])
                    start = start + len(host)
                    conn = bytes('Connection: ' + http.headers['connection'],
                                 encoding='utf-8') + b'\r\n'
                    dict_pcap.append(['http.conn', start, start + len(conn) - 1])
                    start = start + len(conn)
                    try:
                        uir = bytes('Upgrade-Insecure-Requests: ' + http.headers['upgrade-insecure-requests'],
                                    encoding='utf-8') + b'\r\n'
                        dict_pcap.append(['dnt', start, start + len(uir) - 1])
                        start = start + len(uir)
                    except:
                        pass
                    user = bytes('User-Agent: ' + http.headers['user-agent'],
                                 encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.user', start, start + len(user)-1])
                    start = start + len(user)
                    accept = bytes('Accept: '+ http.headers['accept'],
                                   encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.accept', start, start + len(accept)-1])
                    start = start + len(accept)
                    acceptlg = bytes('Accept-Language: ' + http.headers['accept-language'],
                                     encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.acceptlg', start, start + len(acceptlg)-1])
                    start = start + len(acceptlg)
                    accepten = bytes('Accept-Encoding: ' + http.headers['accept-encoding'],
                                     encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.accepten', start, start + len(accepten)-1])
                    start = start + len(accepten)
                    cookie = bytes('Cookie: ' + http.headers['cookie'],
                                   encoding = 'utf-8')+ b'\r\n'
                    dict_pcap.append(['http.cookie', start, start + len(cookie)-1])
                    start = start + len(cookie)
                    try:
                        dnt =  bytes('DNT: ' + http.headers['dnt'],
                                     encoding = 'utf-8')+ b'\r\n\r\n'
                        dict_pcap.append(['dnt', start, start + len(dnt) - 1])
                        start = start + len(dnt)
                    except:
                        pass
        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ipv6 = eth.data
            proto = ipv6.p
            ipdata = ipv6.data
            dict_pcap.extend([['ip6.vtf', start, start+3],
                              ['ip6.pl', start + 4, start + 5],
                              ['ip6.p', start + 6, start + 6],
                              ['ip6.hl', start + 7, start + 7],
                              ['ip6.src', start + 8, start + 23],
                              ['ip6.dst', start + 24, start + 39]])
            start = start + 40

        if proto == dpkt.ip.IP_PROTO_UDP:
            udp = ipdata
            dict_pcap.extend([['udp.dport', start, start + 1],
                              ['udp.sport', start + 2, start + 3],
                              ['udp.len', start + 4, start + 5],
                              ['udp.sum', start + 6, start + 7]])
            start = start + 8
            if (udp.sport == 53) or (udp.dport == 53):
                dns = udp.data
                dlen = len(dns)
                dict_pcap.extend([['dns.id', start, start + 1],
                                  ['dns.flags', start + 2, start + 3],
                                  ['dns.qt', start + 4, start + 5],
                                  ['dns.ansRR', start + 6, start + 7],
                                  ['dns.authRR', start + 8, start + 9],
                                  ['dns.addRR', start + 10, start + 11],
                                  ['dns.quer', start + 12, start + dlen - 1]])
            if (udp.sport == 123) or (udp.dport == 123):
                ntp = udp.data
                dict_pcap.extend([['ntp.vpeer', start, start + 3],
                                  ['ntp.rdelay', start + 4, start + 7],
                                  ['ntp.rdis', start + 8, start + 11],
                                  ['ntp.id', start + 12, start + 15],
                                  ['ntp.reftime', start + 16, start + 23],
                                  ['ntp.otime', start + 24, start + 31],
                                  ['ntp.rectime', start + 32, start + 39],
                                  ['ntp.ttime', start + 40, start + 47]])
            if (udp.sport == 546) or (udp.dport == 546):
                dict_pcap.extend([['dhcp.mtype', start, start],
                                  ['dhcp.tid', start + 1, start + 3],
                                  ['dhcp.time', start + 4, start + 9],
                                  ['dhcp.cid', start + 10, start + 27],
                                  ['dhcp.ia', start + 28, start + 43],
                                  ['dhcp.fq', start + 44, start + 57],
                                  ['dhcp.vc', start + 58, start + 75],
                                  ['dhcp.or', start + 76, start + 87]])
            if (udp.dport == 443) or (udp.sport == 443):
                quic = udp.data
                dict_pcap.append(['quic', start, start + len(quic)-1])
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        if start < endp:
            u = endp - start - 1
            dict_pcap.append(['unknow', start, start + u])
        pass
    return dict_pcap


def analysis_pcap(pcap_file):
    """Отобразить структуру pcap-файла по сетевым протоколам в виде матрицы.

    Параметры:
    pcap_file -- dpkt.pcap.Reader
        Объект pcap.

    Выход:
    dictionary_pcap - DataFrame
        Матрица структуры pcap-файла. Столбцы: word - поле протокола,
                                               start - порядкой номер байта начала,
                                               end - порядкой номер байта конца.
    """
    start = 0                                                       # Указатель на позицию байта.
    dpcap = list()
    for ts, buf in pcap_file:
        dictry_words = parse_packet(buf, start)                     # Распарсить сетевой пакет.
        dpcap = dpcap + dictry_words
        start = start + len(buf)
    matrix_pcap = pd.DataFrame(dpcap,
                               columns=['word', 'start', 'end'])
    dictionary_pcap = matrix_pcap['word'].drop_duplicates()         # Словарь полей сетевых протоколов.
    dictionary_pcap.index = range(1, dictionary_pcap.shape[0] + 1)
    indexlist = list()
    matrix_pcap['index'] = matrix_pcap['word'].map(lambda word:
                                                   dictionary_pcap[dictionary_pcap == word].index.values[0])
    # for index, row in matrix_pcap.iterrows():
    #     #print(index) 63.92
    #     word = row['word']
    #     ix = dictionary_pcap[dictionary_pcap == word].index.values[0]
    #     indexlist.append(ix)
    #matrix_pcap['index'] = pd.Series(indexlist)
    matrix_pcap = matrix_pcap.sort_values('start')
    return [matrix_pcap, dictionary_pcap]


def create_heatmap(data, img_name):
    """Визуализация структуры СТ в виде тепловой карты.

    Параметры:
    data - array
        Массив с индексами полей сетевых протоколов по байтам.
    img_name - string
        Имя файла для сохранения изображения.

    Выход:
        Файл png тепловой карты структуры файла.
    """
    len_data = len(data)
    if len_data > 30000:                                # Разделить данные, если массив большой для отображения.
        n = math.ceil(len_data / 30000)
        e1 = 0
        e2 = 29999
        ardata = []
        for i in range(n):
            ardata.append(data[e1:e2])
            e1 = e2 + 1
            e2 = min(e2 + 30000, len_data)
    else:
        ardata = [data]
    num = 1
    for data in ardata:
        y = 100
        x = round(len(data)/y)+1
        data = np.append(data, np.repeat(np.nan, x*y-data.size))
        data.shape = (x,y)

        top_margin = 0.04                                           # Ширина верхнего поля.
        bottom_margin = 0.04                                        # Ширина нижнего поля.
        left_margin = 0.04                                          # Ширина  поля слева.
        right_margin = 0.96                                         # Ширина  поля справа.

        data2 = data[~np.isnan(data)]
        dmax = data2.max()                                          # Максимальное значение.

        fontsize_pt = 8                                             # Размер шрифта.
        dpi = 72.27
        fontsize_pt = fontsize_pt * len(str(dmax)) + 2              # Размер ячейки.

        matrix_height_pt = fontsize_pt * data.shape[0]              # Высота матрицы.
        matrix_width_pt = fontsize_pt * data.shape[1]               # Ширина матрицы
        matrix_height_in = matrix_height_pt / dpi                   # В дюймах.
        matrix_width_in = matrix_width_pt / dpi
        figure_height = matrix_height_in / (1 - top_margin - bottom_margin)
        figure_width = matrix_width_in                              # Высота и ширина фигуры.

        # if (figure_height*100 > 65535):
        #     figure_width = (65535/figure_height)*figure_width
        #     figure_height = 65535

        fig, (cbar_ax, ax) = plt.subplots(
            2,
            figsize=(figure_width, figure_height),
            gridspec_kw=dict(top=1-top_margin, bottom=bottom_margin,
                             left=left_margin, right= right_margin,
                             height_ratios =[0.01, 0.9], hspace=0.1))

        sns.set(font_scale=1.5)
        ax = sns.heatmap(data, cbar_ax=cbar_ax,
                         ax=ax, annot=True,
                         fmt=".0f", linewidths=.5, linecolor='black',
                         cbar_kws={"orientation": "horizontal"},
                         cmap = 'Spectral')

        plt.savefig(img_name + '-heatmap' + str(num) + '.png', dpi=100)
        num = num + 1


if __name__ == '__main__':
    # Загрузка данных сетевого трафика в формате pcap.
    while 1:
        #pcap_file_name = input('Enter the name of pcap-file: ')
        pcap_file_name = 'dump003'
        try:
            pcap_file = dpkt.pcap.Reader(open('data-test/' + pcap_file_name + '.pcap', 'rb'))
        except:
            print("File doesn't exist. Try again.")
        else:
            break
    # Анализ структуры по сетевым протоколам.
    dictionary_pcap = analysis_pcap(pcap_file)
    dictionary_pcap[1].to_csv('data-result/' + pcap_file_name + '-dict.csv')
    # Составление списка индексов.
    byte_struct = get_list_ID(dictionary_pcap[0])
    # Визуализация.
    create_heatmap(byte_struct, 'data-result/' + pcap_file_name)
