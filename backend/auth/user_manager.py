from auth.hashing_contraseña import hashear_contraseña, verificar_contraseña
from storage.store_usuario import StoreUsuario
import os
import subprocess
import re

class UserManager:
    def __init__(self):
        self.usuario_store = StoreUsuario()
        # Ruta al directorio donde está todo lo de pki
        self.pki_directorio = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'pki')

    def validar_fortaleza_contraseña(self, contraseña: str) -> bool:
        pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>\-_]).{8,}$'
        return bool(re.match(pattern, contraseña))
    
    def _generar_claves_openssl(self, usuario, contraseña):
        """Genera claves usando comandos de OpenSSL"""
        # Crear el directorio de pki del usuario
        user_dir = os.path.join(self.pki_directorio, 'usuarios', usuario)
        os.makedirs(user_dir, exist_ok=True)
        # Ruta a la AC2
        ac2_dir = os.path.join(self.pki_directorio, 'AC2')
        
        try:
            # Generar clave privada (.pem) (cifrada con la contraseña del usuario)
            cmd_key = [
                'openssl', 'genrsa', '-aes256', # ciframos clave usando aes256
                '-passout', f'pass:{contraseña}', # contraseña del usuario para cifrar la clave
                '-out', os.path.join(user_dir, 'private_key.pem'), # ruta a la clave privada
                '2048'
            ]
            subprocess.run(cmd_key, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Generar solicitud de certificado (CSR) 
            csr_path = os.path.join(user_dir, 'usuario.csr')
            cmd_csr = [
                'openssl', 'req', '-new', 
                '-key', os.path.join(user_dir, 'private_key.pem'), # ruta a la clave privada
                '-out', csr_path, # ruta a la solicitud de certificado
                '-passin', f'pass:{contraseña}', # contraseña del usuario para descifrar la clave privada
                '-subj', f'/C=ES/ST=MADRID/O=UC3M/OU=Usuarios/CN={usuario}' # datos del usuario
            ]            
            subprocess.run(cmd_csr, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # La AC2 FIRMA la solicitud del usuario
            cert_final_path = os.path.join(user_dir, 'certificate.pem')
            
            cmd_sign = (
                f"openssl ca -config {os.path.join(ac2_dir, 'openssl_AC2.cnf')} "
                f"-in {csr_path} "
                f"-out {cert_final_path} "
                f"-batch -notext"
            )
            
            # Ejecutamos desde el directorio de AC2 para que encuentre sus carpetas (index.txt, etc)
            subprocess.run(cmd_sign, shell=True, check=True, cwd=ac2_dir, 
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            return True
        
        except subprocess.CalledProcessError as e:
            print(f"Error PKI OpenSSL: {e}")
            if e.stderr: print(f"Detalle: {e.stderr.decode()}")
            return False
        
    def registrar_usuario(self, usuario: str, contraseña: str) -> int:
        """Registra un nuevo usuario"""

        # Comprobamos si el usuario ya existe
        if self.usuario_store.usuario_existe(usuario):
            return 0
        
        # Validamos la fortaleza de la contraseña
        if not self.validar_fortaleza_contraseña(contraseña):
            return 2
        
        # Si todo está bien, hasheamos y guardamos
        sal, hash_contraseña = hashear_contraseña(contraseña)
        if (self.usuario_store.guardar_usuario(usuario, sal, hash_contraseña)):
            # Generamos las claves PKI para el usuario
            if self._generar_claves_openssl(usuario, contraseña):
                return 1
            else:
                # Si hay un fallo en PKI se elimina el usuario
                print(f"Fallo en PKI. Eliminando usuario {usuario} para evitar inconsistencia.")
                self.usuario_store.eliminar_usuario(usuario)
                return -1
        else:
            return -1
    
    def autenticar_usuario(self, usuario: str, contraseña: str) -> bool:
        """Autentica un usuario"""
        datos_usuario = self.usuario_store.obtener_datos_usuario(usuario)
        if not datos_usuario:
            return False
        
        return verificar_contraseña(contraseña, datos_usuario["sal"], datos_usuario["hash_contraseña"])
