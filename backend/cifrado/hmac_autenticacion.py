import hmac
import hashlib
import secrets
import base64

class HMACGenerator:
    @staticmethod
    def generar_clave_hmac() -> bytes:
        """Genera una clave aleatoria para HMAC de 32 bytes"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def calcular_hmac(mensaje: str, clave: bytes) -> str:
        """Calcula HMAC-SHA256 de un mensaje"""
        objeto_hmac = hmac.new(clave, mensaje.encode("utf-8"), hashlib.sha256)
        return base64.b64encode(objeto_hmac.digest()).decode("utf-8")
    
    @staticmethod
    def verificar_hmac(mensaje: str, hmac_recibido: str, clave: bytes) -> bool:
        """Verifica HMAC"""
        hmac_calculado = HMACGenerator.calcular_hmac(mensaje, clave)
        return hmac.compare_digest(hmac_calculado, hmac_recibido)
