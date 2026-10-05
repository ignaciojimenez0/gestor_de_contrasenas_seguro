from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

class CifradoHibrido:
    def __init__(self):

        # Ruta al directorio donde está todo lo de pki
        self.pki_directorio = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'pki')

    def _cargar_publica(self, usuario):
        """Carga la clave pública de un usuario"""
        # Calcular la ruta al certificado
        ruta_cert = os.path.join(self.pki_directorio, 'usuarios', usuario, 'certificate.pem')
        # Abrir el archivo y leer la clave pública
        with open(ruta_cert, "rb") as file:
            cert_data = file.read()
            # backend devuelve el backend de OpenSSL. Indicando que se va a usar OpenSSL
            cert = x509.load_pem_x509_certificate(cert_data, default_backend()) # Esta función carga el certificado
            return cert.public_key()

    def _cargar_privada(self, usuario, contraseña_maestra):
        """Carga la clave privada de un usuario, necesitando su contraseña maestra"""
        # Calcular la ruta al certificado
        ruta_priv = os.path.join(self.pki_directorio, 'usuarios', usuario, 'private_key.pem')
        # Abrir el archivo y leer
        with open(ruta_priv, "rb") as file:
            return serialization.load_pem_private_key(
                file.read(),
                password=contraseña_maestra.encode(),
                backend=default_backend()
            ) # Esta función carga la clave privada
        

    def cifrar_hibrido(self, usuario, mensaje_secreto):
        """Cifra el mensaje con AES y la clave AES con RSA.
        NO calcula HMAC (eso lo hace el manager)"""
        # Generar clave AES aleatoria y nonce aleatorio
        clave_aes = os.urandom(32)
        nonce = os.urandom(16)

        # Cifrar datos con AES
        cipher = Cipher(algorithms.AES(clave_aes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        datos_cifrados = encryptor.update(mensaje_secreto.encode('utf-8')) + encryptor.finalize()

        # Cifrar clave AES con RSA (Clave Pública del usuario)
        public_key = self._cargar_publica(usuario)
        clave_aes_cifrada = public_key.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Devolver los datos
        return {
            "datos_cifrados": base64.b64encode(datos_cifrados).decode('utf-8'),
            "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8')
        }

    def descifrar_hibrido(self, usuario, contraseña_maestra, datos_json):
        """Recupera la clave AES usando RSA y luego descifra el mensaje"""
        # Recuperar datos y decodificar
        b64_datos = datos_json.get("contraseña_cifrada") or datos_json.get("datos_cifrados")        
        datos_cifrados = base64.b64decode(b64_datos)
        clave_aes_cifrada = base64.b64decode(datos_json["clave_aes_cifrada"])
        nonce = base64.b64decode(datos_json["nonce"])

        # Recuperar clave AES (cifrada con RSA)
        clave_priv = self._cargar_privada(usuario, contraseña_maestra)
        clave_aes = clave_priv.decrypt(
            clave_aes_cifrada,
            padding.OAEP( # padding para aletoriedad
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )

        # Descifrar mensaje (con la clave AES obtenida anteriormente)
        cipher = Cipher(algorithms.AES(clave_aes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        mensaje = decryptor.update(datos_cifrados) + decryptor.finalize() # finalize indica que hemos terminado de descifrar

        return mensaje.decode('utf-8')

    def cifrar_dato_rsa(self, usuario, datos_bytes):
        """Helper para cifrar cualquier dato pequeño (como la clave HMAC) con RSA (no híbrido)"""
        # Cargar la clave pública
        public_key = self._cargar_publica(usuario)
        # Cifrar
        cifrado = public_key.encrypt(
            datos_bytes,
            padding.OAEP( # padding para aletoriedad
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(cifrado).decode('utf-8')

    def descifrar_dato_rsa(self, usuario, contraseña_maestra, datos_b64):
        """Helper para descifrar cualquier dato pequeño con RSA"""
        # Decodificar los datos
        datos_cifrados = base64.b64decode(datos_b64)
        # Cargar la clave privada
        private_key = self._cargar_privada(usuario, contraseña_maestra)
        # Descifrar
        datos_planos = private_key.decrypt(
            datos_cifrados,
            padding.OAEP( # padding para aletoriedad
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return datos_planos

    def firmar_datos(self, usuario, contraseña_maestra, datos_a_firmar):
        """Genera firma digital RSA-SHA256"""
        # Cargar la clave privada
        private_key = self._cargar_privada(usuario, contraseña_maestra)
        # Firmar
        signature = private_key.sign(
            datos_a_firmar.encode('utf-8'),
            padding.PSS( # padding para aletoriedad 
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verificar_firma(self, usuario, datos_originales, firma_b64):
        """Verifica firma digital RSA-SHA256 usando el certificado público"""
        # Cargar la clave pública
        public_key = self._cargar_publica(usuario)
        # Verificar
        try:
            signature = base64.b64decode(firma_b64)
            public_key.verify(
                signature,
                datos_originales.encode('utf-8'),
                padding.PSS( # padding para aletoriedad
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
