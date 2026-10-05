import json
import base64
import os

class StoreUsuario:
    def __init__(self, filename="data/users.json"):
        self.filename = filename
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    def usuario_existe(self, usuario: str) -> bool:
        """Comprueba si un usuario existe"""
        usuarios = self._cargar_usuarios()
        return usuario in usuarios
    
    def guardar_usuario(self, usuario: str, sal: bytes, hash_contraseña: bytes) -> bool:
        """Guarda un nuevo usuario"""
        usuarios = self._cargar_usuarios()
        
        usuarios[usuario] = {
            "sal": base64.b64encode(sal).decode("utf-8"),
            "hash_contraseña": base64.b64encode(hash_contraseña).decode("utf-8")
        }
        return self._guardar_usuarios(usuarios)
    
    def obtener_datos_usuario(self, usuario: str):
        """Obtiene los datos de un usuario"""
        usuarios = self._cargar_usuarios()
        datos_usuario = usuarios.get(usuario)
        if datos_usuario:
            return {
                "sal": base64.b64decode(datos_usuario["sal"]),
                "hash_contraseña": base64.b64decode(datos_usuario["hash_contraseña"])
            }
        return None
    
    def eliminar_usuario(self, usuario: str) -> bool:
        """Elimina un usuario del registro (Rollback)
        Usaremos esta funcion en caso de que algo salga mal
        durante el registro de un usuario"""
        usuarios = self._cargar_usuarios()
        if usuario in usuarios:
            del usuarios[usuario]
            return self._guardar_usuarios(usuarios)
        return False

    def _cargar_usuarios(self):
        try:
            with open(self.filename, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _guardar_usuarios(self, users):
        try:
            with open(self.filename, "w") as f:
                json.dump(users, f, indent=2)
            return True
        except Exception as e:
            print(f"Error guardando usuarios: {e}")
            return False
