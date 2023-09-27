import csv
import paramiko
import json

with open('config.json', 'r') as file:
    config = json.load(file)

inventory = config['inventory']

with open('user.json', 'r') as user_file:
    user = json.load(user_file)

inventory = config['inventory']
user_name = user['user' ]
user_password = user['password']
user_public_key = user['public_key']
user_type =  user['user_type']

def probar_conexion(ip, puerto, usuario, contrasena):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_de_prueba = f"hostname"
        stdin, stdout, stderr = ssh.exec_command(comando_de_prueba)
        print(stdout.read().decode())
        ssh.close()
    except Exception as e:
        print(f"Error al crear usuario en {ip}:{puerto}: {str(e)}")

def crear_usuario_ssh(ip, puerto, usuario, contrasena, nuevo_usuario, nuevo_usuario_password, clave_publica):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)

        comando_creacion_usuario = f"useradd -m -aG wheel sudo {nuevo_usuario}"
        comando_cambio_contraseña = f"echo '{nuevo_usuario}:{nuevo_usuario_password}' | sudo chpasswd"
        comando_agregar_clave = f"sudo -u {nuevo_usuario} mkdir -p /home/{nuevo_usuario}/.ssh && sudo -u {nuevo_usuario} echo '{clave_publica}' >> /home/{nuevo_usuario}/.ssh/authorized_keys"

        stdin, stdout, stderr = ssh.exec_command(comando_creacion_usuario)
        print(stdout.read().decode())
        
        stdin, stdout, stderr = ssh.exec_command(comando_cambio_contraseña)
        print(stdout.read().decode())

        stdin, stdout, stderr = ssh.exec_command(comando_agregar_clave)
        print(stdout.read().decode())

        ssh.close()
        print(f"Usuario {nuevo_usuario} creado en {ip}:{puerto}")

    except Exception as e:
        print(f"Error al crear usuario en {ip}:{puerto}: {str(e)}")

def crear_usuario(ip, puerto, usuario, contrasena, nuevo_usuario):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_creacion_usuario = f"useradd -m {nuevo_usuario}"
        stdin, stdout, stderr = ssh.exec_command(comando_creacion_usuario)
        print(stdout.read().decode())
        ssh.close()
        print(f"Usuario {nuevo_usuario} creado en {ip}:{puerto}")
    except Exception as e:
        print(f"Error al crear usuario en {ip}:{puerto}: {str(e)}")

def eliminar_usuario(ip, puerto, usuario, contrasena, usuario_a_eliminar):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_eliminar_usuario = f"userdel --remove  {usuario_a_eliminar}"
        stdin, stdout, stderr = ssh.exec_command(comando_eliminar_usuario)
        print(stdout.read().decode())
        ssh.close()
        print(f"Usuario {usuario_a_eliminar} eliminado en {ip}:{puerto}")
    except Exception as e:
        print(f"Error al eliminar usuario en {ip}:{puerto}: {str(e)}")

def agregar_usuario_a_grupo(ip, puerto, usuario, contrasena, nuevo_usuario, grupo):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_agregar_grupo = f"usermod -aG {grupo} {nuevo_usuario}"
        stdin, stdout, stderr = ssh.exec_command(comando_agregar_grupo)
        print(stdout.read().decode())
        ssh.close()
        print(f"Usuario {nuevo_usuario} agregado al grupo {grupo} en {ip}:{puerto}")
    except Exception as e:
        print(f"Error al agregar usuario a grupo en {ip}:{puerto}: {str(e)}")

def agregar_llave_publica_a_usuario(ip, puerto, usuario, contrasena, nuevo_usuario, llave_publica):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_agregar_llave = f"sudo -u {nuevo_usuario} mkdir -p /home/{nuevo_usuario}/.ssh && sudo -u {nuevo_usuario} echo '{llave_publica}' >> /home/{nuevo_usuario}/.ssh/authorized_keys"
        stdin, stdout, stderr = ssh.exec_command(comando_agregar_llave)
        print(stdout.read().decode())
        ssh.close()
        print(f"Llave agregada al Usuario {nuevo_usuario} en {ip}:{puerto}")
    except Exception as e:
        print(f"Error al agregar llave a usuario  en {ip}:{puerto}: {str(e)}")

def asignar_contrasena(ip, puerto, usuario, contrasena, nuevo_usuario, nueva_contrasena):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=puerto, username=usuario, password=contrasena)
        comando_asignar_contrasena = f"echo '{nuevo_usuario}:{nueva_contrasena}' | sudo chpasswd"
        stdin, stdout, stderr = ssh.exec_command(comando_asignar_contrasena)
        print(stdout.read().decode())
        print(f"Contraseña agregada al Usuario {nuevo_usuario} en {ip}:{puerto}")
    except Exception as e:
        print(f"Error al agregar contraseña a usuario  en {ip}:{puerto}: {str(e)}")

with open(inventory, mode='r') as file:
    csv_reader = csv.DictReader(file, delimiter=';')
    for row in csv_reader:
        ip = row['IP']
        puerto = row['PORT']
        usuario = row['USER']
        contrasena = row['PASSWORD']
        print(f"{ip},{puerto},{usuario},{contrasena}")
        print(f"{user_name},{user_password},{user_public_key}")
        #eliminar_usuario(ip, puerto, usuario, contrasena, user_name)
        crear_usuario(ip, puerto, usuario, contrasena, user_name)
        asignar_contrasena(ip, puerto, usuario, contrasena, user_name, user_password)
        agregar_llave_publica_a_usuario(ip, puerto, usuario, contrasena, user_name, user_public_key)
        if user_type == "root":
            print(user_type)
            agregar_usuario_a_grupo(ip, puerto, usuario, contrasena, user_name,'wheel')
