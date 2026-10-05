import json
import os
from clases.contraseña import Contraseña

class StoreContraseña:
    def __init__(self, filename="data/passwords.json"):
        self.filename = filename
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    def guardar_contraseña(self, usuario: str, servicio: str, datos_encriptados: dict, correo: str) -> bool:
        """Guarda una nueva contraseña para un usuario"""
        # Cargamos todas las contraseñas
        todas_contraseñas = self._cargar_contraseñas()
        
        # Comprobamos si el usuario no tiene entradas
        if usuario not in todas_contraseñas:
            todas_contraseñas[usuario] = []
        
        # Cremoas nueva entrada
        entrada_nueva = Contraseña(servicio, datos_encriptados, correo)
        
        # Comprobamos si ya existe una entrada con ese mismo correo
        for entrada in todas_contraseñas[usuario]:
            if entrada["servicio"] == servicio and entrada["correo"] == correo:
                return False  

        # Añadir la nueva entrada
        todas_contraseñas[usuario].append(entrada_nueva.a_diccionario())
        
        return self._guardar_contraseñas(todas_contraseñas)
    
    def obtener_contraseña(self, usuario: str, servicio: str, correo: str) -> dict:
        """Obtiene los datos cifrados de una contraseña por servicio Y correo"""
        contraseñas = self._cargar_contraseñas()
        contraseñas_usuario = contraseñas.get(usuario, [])
        
        for datos_entrada in contraseñas_usuario:
            if datos_entrada["servicio"] == servicio and datos_entrada["correo"] == correo:
                return datos_entrada["datos_encriptados"]
        return None
    
    def listar_todos_los_servicios(self, usuario: str) -> list:
        """
        Obtiene todos los servicios de un usuario
        """
        contraseñas = self._cargar_contraseñas()
        contraseñas_usuario = contraseñas.get(usuario, [])
        
        # Retornamos solo servicio y correo
        resultado = []
        for entrada in contraseñas_usuario:
            datos = {
                "servicio": entrada["servicio"],
                "correo": entrada["correo"]
            }
            resultado.append(datos)
        return resultado

    def eliminar_contraseña(self, usuario: str, servicio: str, correo: str) -> bool:
        """Elimina una contraseña específica por servicio y correo"""
        contraseñas = self._cargar_contraseñas()
        
        if usuario not in contraseñas:
            return False
        
        numero_contraseñas_antes = len(contraseñas[usuario])
        contraseñas[usuario] = [
            entrada for entrada in contraseñas[usuario] 
            if not (entrada["servicio"] == servicio and entrada["correo"] == correo)
        ]
        
        if len(contraseñas[usuario]) < numero_contraseñas_antes:
            return self._guardar_contraseñas(contraseñas)
        return False
    
    def _cargar_contraseñas(self):
        """Cargar todas las contraseñas"""
        try:
            with open(self.filename, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _guardar_contraseñas(self, contraseñas):
        """Guardar las contraseñas al json"""
        try:
            with open(self.filename, "w") as f:
                json.dump(contraseñas, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error guardando contraseñas: {e}")
            return False
