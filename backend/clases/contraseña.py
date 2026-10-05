class Contraseña:
    def __init__(self, servicio: str, datos_encriptados: dict, correo: str):
        self.servicio = servicio

        self.datos_encriptados = datos_encriptados  

        self.correo = correo
    
    def a_diccionario(self):
        return {
            "servicio": self.servicio,
            "datos_encriptados": self.datos_encriptados,
            "correo": self.correo
        }
