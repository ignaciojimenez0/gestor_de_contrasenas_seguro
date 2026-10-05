from storage.store_contraseña import StoreContraseña
from cifrado.hmac_autenticacion import HMACGenerator
from cifrado.cifrado_hibrido import CifradoHibrido

class PasswordManager:
    def __init__(self):
        self.contraseña_store = StoreContraseña()
        self.encryptor = CifradoHibrido()
    
    def entrada_existe(self, usuario: str, servicio: str, correo: str) -> bool:
        """
        Verifica si ya existe una entrada con el mismo servicio y correo
        """
        todas_las_contraseñas = self.contraseña_store.listar_todos_los_servicios(usuario)
        for entrada in todas_las_contraseñas:
            if (entrada["servicio"].lower() == servicio.lower() and 
                entrada["correo"].lower() == correo.lower()):
                return True
        return False

    def añadir_contraseña(self, usuario: str, servicio: str, contraseña: str, contraseña_maestra: str, correo: str) -> bool:
        """
        Añade una nueva contraseña con HMAC
        """
        if self.entrada_existe(usuario, servicio, correo):
            return False
        
        try:
            # Cifrar datos (Híbrido)
            datos_encriptados = self.encryptor.cifrar_hibrido(usuario, contraseña)
            contraseña_cifrada_b64 = datos_encriptados["datos_cifrados"]
            
            # Generar clave HMAC
            clave_hmac = HMACGenerator.generar_clave_hmac()
            
            # Cifrar clave HMAC (RSA)
            clave_hmac_encriptada = self.encryptor.cifrar_dato_rsa(
                usuario,
                clave_hmac
            )
            
            # Calcular HMAC
            hmac_comprobante = HMACGenerator.calcular_hmac(contraseña_cifrada_b64, clave_hmac)
            
            # Firmamos la contraseña cifrada para garantizar autoría
            firma_digital = self.encryptor.firmar_datos(usuario, contraseña_maestra, contraseña_cifrada_b64)

            # Guardar todo
            todos_datos_encriptados = {
                "contraseña_cifrada": contraseña_cifrada_b64,
                "clave_aes_cifrada": datos_encriptados["clave_aes_cifrada"],
                "nonce": datos_encriptados["nonce"],
                "clave_hmac_encriptada": clave_hmac_encriptada,
                "hmac_comprobante": hmac_comprobante,
                "firma_digital": firma_digital
            }
            
            return self.contraseña_store.guardar_contraseña(usuario, servicio, todos_datos_encriptados, correo)
        except Exception as e:
            print(f"Error añadiendo contraseña: {e}")
            return False
    
    def obtener_contraseña(self, usuario: str, servicio: str, contraseña_maestra: str, correo: str) -> str:
        """
        Obtiene y descifra una contraseña específica por servicio y correo
        """
        datos_encriptados = self.contraseña_store.obtener_contraseña(usuario, servicio, correo)
        if not datos_encriptados:
            return None
        
        try:
            # Descifrar la clave HMAC
            clave_hmac = self.encryptor.descifrar_dato_rsa(
                usuario,
                contraseña_maestra,
                datos_encriptados["clave_hmac_encriptada"]
            )

            # Verificar HMAC
            contraseña_cifrada = datos_encriptados["contraseña_cifrada"]
            hmac_almacenado = datos_encriptados["hmac_comprobante"]
            
            # Verificamos Firma Digital
            firma = datos_encriptados.get("firma_digital")
            if firma:
                if not self.encryptor.verificar_firma(usuario, contraseña_cifrada, firma):
                    print("ALERTA: Firma digital inválida. El autor no parece legítimo.")
                    # Aquí decides si bloqueas o solo avisas. Para nota alta, bloquea.
                    return None

            if not HMACGenerator.verificar_hmac(contraseña_cifrada, hmac_almacenado, clave_hmac):
                print("Error de integridad: El HMAC no coincide")
                return None
            
            mensaje_plano = self.encryptor.descifrar_hibrido(usuario, contraseña_maestra, datos_encriptados)
            return mensaje_plano
        except Exception as e:
            print(f"Error obteniendo contraseña: {e}")
            return None
            
    def actualizar_contraseña(self, usuario: str, servicio: str, contraseña_nueva: str, contraseña_maestra: str, correo: str) -> bool:
        resultado = self.contraseña_store.eliminar_contraseña(usuario, servicio, correo)
        if not resultado:
            return False
        return self.añadir_contraseña(usuario, servicio, contraseña_nueva, contraseña_maestra, correo)
        
    def eliminar_entrada(self, usuario: str, servicio: str, correo: str) -> bool:
        return self.contraseña_store.eliminar_contraseña(usuario, servicio, correo)
    
    def listar_servicios(self, usuario: str) -> list:
        return self.contraseña_store.listar_todos_los_servicios(usuario)
