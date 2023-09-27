import subprocess
import sys

def generar_llave_ssh(usuario_comentario, ubicacion_archivo):
    comando = f'ssh-keygen -t ed25519 -C "{usuario_comentario}" -N "" -f "{ubicacion_archivo}"'
    try:
        subprocess.run(comando, shell=True)
        print("Llave SSH generada exitosamente.")
    except subprocess.CalledProcessError as e:
        print(f"Error al generar la llave SSH: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generar_llave_ssh.py <usuario_comentario> <ubicacion_archivo>")
    else:
        usuario_comentario = sys.argv[1]
        ubicacion_archivo = sys.argv[2]
        generar_llave_ssh(usuario_comentario, ubicacion_archivo)

