import hashlib
import secrets

# Número de iteraciones para hacer el hash más lento y resistente, 
# ya que un atacante tarda 100.000 veces más por cada ataque de
# fuerza bruta, y vuelve inviable este tipo de ataques
ITERATIONS = 100000

def hashear_contraseña(contraseña: str) -> tuple[bytes, bytes]:
    """Hashea una contraseña usando SHA-256 con 100.000 iteraciones"""
    # Generamos una sal única de 32 bytes para aletoriedad
    sal = secrets.token_bytes(32)
    
    # Hasheamos 1 vez
    hash = hashlib.sha256(sal + contraseña.encode("utf-8")).digest()
    
    # Hasheamos el resto de veces
    for i in range(ITERATIONS - 1):
        hash = hashlib.sha256(hash).digest()
    
    return sal, hash

def verificar_contraseña(contraseña: str, sal: bytes, hash_almaceando: bytes) -> bool:
    """Calcula el hash de una contraseña y lo compara con el hash almacenado para verificar"""
    # Repetimos el mismo proceso de hashing
    hash_nuevo = hashlib.sha256(sal + contraseña.encode("utf-8")).digest()
    
    for i in range(ITERATIONS - 1):
        hash_nuevo = hashlib.sha256(hash_nuevo).digest()
    
    # Comparamos con el hash almacenado 
    return secrets.compare_digest(hash_nuevo, hash_almaceando)
