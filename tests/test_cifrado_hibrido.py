import unittest
from unittest.mock import patch
import os
import sys
import shutil
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Añadir backend al path para permitir importaciones
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.cifrado.cifrado_hibrido import CifradoHibrido

class TestCifradoHibrido(unittest.TestCase):

    def setUp(self):
        self.cifrador = CifradoHibrido()
        
        # Generar claves mock para las pruebas
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self.test_user = "usuario_prueba"
        self.test_password = "password_prueba"

    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_publica')
    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_privada')
    def test_cifrado_descifrado_hibrido(self, mock_cargar_privada, mock_cargar_publica):
        """Prueba el ciclo completo de cifrado y descifrado híbrido"""
        # Configurar mocks
        mock_cargar_publica.return_value = self.public_key
        mock_cargar_privada.return_value = self.private_key

        mensaje_original = "Mensaje de prueba a cifrar"
        
        # 1. Cifrar
        resultado = self.cifrador.cifrar_hibrido(self.test_user, mensaje_original)
        
        # Comprobar que el resultado tiene los componentes esperados
        self.assertIn("datos_cifrados", resultado)
        self.assertIn("clave_aes_cifrada", resultado)
        self.assertIn("nonce", resultado)
        
        # 2. Descifrar
        mensaje_recuperado = self.cifrador.descifrar_hibrido(
            self.test_user, 
            self.test_password, 
            resultado
        )
        
        # Comprobar que el mensaje recuperado es el esperado
        self.assertEqual(mensaje_original, mensaje_recuperado)

    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_publica')
    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_privada')
    def test_firma_verificacion(self, mock_cargar_privada, mock_cargar_publica):
        """Prueba la firma y verificación usando cryptography"""
        # Configurar mocks
        mock_cargar_publica.return_value = self.public_key
        mock_cargar_privada.return_value = self.private_key

        datos = "Datos importantes para firmar"
        
        # 1. Firmar
        firma_b64 = self.cifrador.firmar_datos(self.test_user, self.test_password, datos)
        self.assertIsInstance(firma_b64, str) # Comprobar que la firma es una cadena de texto
        
        # 2. Verificar firma correcta
        es_valida = self.cifrador.verificar_firma(self.test_user, datos, firma_b64)
        self.assertTrue(es_valida) # Comprobar que la firma es correcta
        
        # 3. Verificar firma incorrecta (datos alterados)
        es_invalida = self.cifrador.verificar_firma(self.test_user, "Datos alterados", firma_b64)
        self.assertFalse(es_invalida) # Comprobar que la firma es incorrecta

    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_publica')
    @patch('backend.cifrado.cifrado_hibrido.CifradoHibrido._cargar_privada')
    def test_cifrado_rsa_puro(self, mock_cargar_privada, mock_cargar_publica):
        """Prueba el cifrado y descifrado RSA puro para datos pequeños"""
        # Configurar mocks
        mock_cargar_publica.return_value = self.public_key
        mock_cargar_privada.return_value = self.private_key

        datos_bytes = b"clave_secreta_corta"
        
        # 1. Cifrar RSA
        cifrado_b64 = self.cifrador.cifrar_dato_rsa(self.test_user, datos_bytes)
        
        # 2. Descifrar RSA
        datos_recuperados = self.cifrador.descifrar_dato_rsa(
            self.test_user, 
            self.test_password, 
            cifrado_b64
        )
        
        self.assertEqual(datos_bytes, datos_recuperados)

    def test_descifrado_password_incorrecta(self):
        """Prueba que falla si la contraseña de la clave privada es incorrecta"""
        # En este caso necesitamos simular que load_pem_private_key falla
        # O podemos usar un mock que lance excepción
        
        with patch('backend.cifrado.cifrado_hibrido.serialization.load_pem_private_key') as mock_load:
            mock_load.side_effect = ValueError("Bad decrypt")
            
            # Necesitamos mockear open también para que no intente leer disco real
            with patch('builtins.open', unittest.mock.mock_open(read_data=b"fake_key_data")):
                with self.assertRaises(ValueError):
                    self.cifrador._cargar_privada("usuario", "wrong_password")

    def test_cargar_claves_integration(self):
        """Prueba de integración: Crear archivos reales y cargarlos"""
        # 1. Crear directorio temporal para usuario test
        test_user_dir = os.path.join(self.cifrador.pki_directorio, 'usuarios', 'test_integration_user')
        os.makedirs(test_user_dir, exist_ok=True)
        
        try:
            # 2. Generar y guardar clave privada
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            pem_priv = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"testpass")
            )
            
            with open(os.path.join(test_user_dir, 'private_key.pem'), 'wb') as f:
                f.write(pem_priv)
                
            # 3. Generar y guardar certificado (clave pública)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"Test User"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=10)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            with open(os.path.join(test_user_dir, 'certificate.pem'), 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                
            # 4. Probar _cargar_privada
            loaded_priv = self.cifrador._cargar_privada('test_integration_user', 'testpass')
            self.assertIsInstance(loaded_priv, rsa.RSAPrivateKey)
            
            # 5. Probar _cargar_publica
            loaded_pub = self.cifrador._cargar_publica('test_integration_user')
            self.assertIsInstance(loaded_pub, rsa.RSAPublicKey)
            
        finally:
            # Limpieza
            if os.path.exists(test_user_dir):
                shutil.rmtree(test_user_dir)

if __name__ == '__main__':
    unittest.main()
