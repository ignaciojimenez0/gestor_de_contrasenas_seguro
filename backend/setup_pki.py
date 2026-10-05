# Todo este archivo es el como se ha creado la estructura de clave publica
# usa subprocess para ejecutar comandos de openssl y asi automatizar todo el proceso
import os
import subprocess

# Rutas base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.path.join(BASE_DIR, 'pki')

# Configuración
AC1_DIR = os.path.join(PKI_DIR, 'AC1')
AC2_DIR = os.path.join(PKI_DIR, 'AC2')

def run_cmd(cmd, cwd=None):
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=cwd, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        print(f"Ejecutado: {cmd[:50]}...")
    except subprocess.CalledProcessError as e:
        print(f"Error en: {cmd}")
        print(e.stderr.decode())
        exit(1)

def inicializar_estructura():
    print("--- INICIALIZANDO PKI (Jerarquía de Confianza) ---")
    
    # Crear carpetas de estructura OpenSSL
    for ac_dir in [AC1_DIR, AC2_DIR]:
        os.makedirs(os.path.join(ac_dir, 'privado'), exist_ok=True)
        os.makedirs(os.path.join(ac_dir, 'nuevoscerts'), exist_ok=True)
        os.makedirs(os.path.join(ac_dir, 'crls'), exist_ok=True)
        os.makedirs(os.path.join(ac_dir, 'certificados'), exist_ok=True)
        
        # Archivos de base de datos de OpenSSL
        index_path = os.path.join(ac_dir, 'index.txt')
        if not os.path.exists(index_path):
            with open(index_path, 'w') as f: pass
            
        serial_path = os.path.join(ac_dir, 'serial')
        if not os.path.exists(serial_path):
            with open(serial_path, 'w') as f: f.write('1000')

    # Necesitamos copiar los .cnf que ya tienes a estas carpetas
    # (Asegúrate de que los archivos openssl_AC1.cnf y openssl_AC2.cnf existen en backend/pki/...)
    
    # --- PASO 1: CREAR AUTORIDAD RAÍZ (AC1) ---
    print("\n1. Generando Autoridad Raíz (AC1)...")
    # Generar clave privada de AC1 (sin password para simplificar el script, en real llevaría)
    run_cmd(f"openssl genrsa -out privado/ca1key.pem 4096", cwd=AC1_DIR)
    
    # Generar certificado autofirmado de AC1
    # IMPORTANTE: Usamos -config openssl_AC1.cnf
    run_cmd(f"openssl req -new -x509 -days 3650 -key privado/ca1key.pem "
            f"-out ac1cert.pem -config openssl_AC1.cnf -batch", cwd=AC1_DIR)


    # --- PASO 2: CREAR AUTORIDAD SUBORDINADA (AC2) ---
    print("\n2. Generando Autoridad Subordinada (AC2)...")
    # Generar clave privada de AC2
    run_cmd(f"openssl genrsa -out privado/ca2key.pem 4096", cwd=AC2_DIR)
    
    # Generar Solicitud de Certificado (CSR) para AC2
    run_cmd(f"openssl req -new -key privado/ca2key.pem -out ac2.csr "
            f"-config openssl_AC2.cnf -batch", cwd=AC2_DIR)
    
    # AC1 firma el certificado de AC2
    print("   -> AC1 está firmando a AC2...")
    # Nota: openssl ca necesita ejecutarse desde el directorio de la CA firmante
    # y apuntar al config correcto.
    run_cmd(f"openssl ca -in ../AC2/ac2.csr -out ../AC2/ac2cert.pem "
        f"-config openssl_AC1.cnf -extensions v3_subca "
        f"-days 1825 "
        f"-batch -notext", cwd=AC1_DIR)

    print("\nPKI Inicializada correctamente.")
    print("Jerarquía: AC1 (Raíz) -> AC2 (Subordinada)")

if __name__ == '__main__':
    inicializar_estructura()
