import csv
import json

def generar_inventario(inventory_file):
    servers_by_so = {}

    with open(inventory_file, mode='r') as file:
        csv_reader = csv.DictReader(file, delimiter=';')

        for row in csv_reader:
            ip = row['IP']
            so = row['SO']
            port = row['PORT']
            user = 'test'
            key = '~/.ssh/test'

            server_info = {'ip': ip, 'port': port, 'user': user}

            if "CentOS" in so:
                nso = "centos"
            elif "RedHat" in so:
                nso = "redhat"
            else:
                nso = "otros"

            if nso not in servers_by_so:
                servers_by_so[nso] = []

            servers_by_so[nso].append(server_info)

    ansible_inventory = {}

    for so, servers in servers_by_so.items():
        ansible_inventory[so] = {
            'hosts': {server['ip']: {"ansible_ssh_port": server['port']} for server in servers},
            'vars': {
                'ansible_user': servers[0]['user'],
                'ansible_ssh_common_args': f'-o StrictHostKeyChecking=no -i {key}',
            }
        }
    return json.dumps(ansible_inventory, indent=4)

with open('config.json', 'r') as file:
    config = json.load(file)

inventory_file_path = config['inventory']

print('Inventario identificado en {}'.format(inventory_file_path))

inventario_json = generar_inventario(inventory_file_path)
print(inventario_json)

