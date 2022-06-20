from tabulate import tabulate
import scapy.all as scapy
import requests
import json

ips = []

def ip_viewer(x):
    global ips, ip

    try:
        ip = x.payload.dst

        if not ip in ips:
            ips.append(ip)

            if not '192.168' in ip:

                try:
                    dados = requests.get(f'http://ip-api.com/json/{ip}')
                except:
                    return 0

                if dados.status_code == 200:

                    resp = json.loads(dados.text)

                    if resp["status"] == 'success':

                        table = [
                            ["Direccion IP:", resp['query']],
                            ["Ciudad:", resp['city']],
                            ["Lat", resp ['lat']],
                            ["Alt", resp ['lon']],
                            ["Estado:", resp['regionName']],
                            ["Departamento:", resp['region']],
                            ["Pais:", resp['country']],
                            ["Codigo Postal:", resp['zip']],
                            ["ISP:", resp['org']]
                        ]
                        print()
                        print(tabulate(table))

                    else:
                        return f"ip: {ip} | Request error {resp['status']}"

                else:
                    return f"ip: {ip} | Error {dados.status_code}"
    except:
        pass


ip = input('Para iniciar el rastreador debes ingresar tu Dirección IP ')

query = ''
if ip:
    query = f' src {ip}'

a = scapy.sniff(iface='Wi-Fi', prn=ip_viewer, filter=f"udp{query}")