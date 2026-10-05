from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import secrets
import re

# Importar directamente desde los subdirectorios
from auth.user_manager import UserManager
from auth.password_manager import PasswordManager

# Configuramos Flask para usar la carpeta frontend como templates
directorio_acutal = os.path.dirname(os.path.abspath(__file__))
directorio_frontend = os.path.join(os.path.dirname(directorio_acutal), 'frontend')

app = Flask(__name__, template_folder=directorio_frontend)
app.secret_key = secrets.token_hex(32)

# Inicializamos managers
manager_usuarios = UserManager()
manager_contraseñas = PasswordManager()

# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

# Ruta registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contraseña = request.form['contraseña']

        resultado = manager_usuarios.registrar_usuario(usuario, contraseña)
        
        if (resultado == 1):
            flash(f'Usuario registrado correctamente | Algoritmo: SHA-256 con 100,000 iteraciones y sal de 32 bytes | Longitud hash: 256 bits | Se ha creado una clave privada y un certificado para este usuario', 'success')
            return redirect(url_for('inicio_sesion'))
        elif (resultado == 0):
            flash('El usuario ya existe', 'error')
        elif (resultado == -1):
            flash('Error al registrar el usuario', 'error')
        elif (resultado == 2):
            flash('Contraseña: longitud mínima de 8, mínimo 1 mayúscula, minimo 1 número, mínimo 1 carácter especial', 'error')
    
    return render_template('registro.html')

# Ruta inicio sesión
@app.route('/inicio_sesion', methods=['GET', 'POST'])
def inicio_sesion():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contraseña = request.form['contraseña']
        
        if manager_usuarios.autenticar_usuario(usuario, contraseña):
            session['usuario'] = usuario
            session['contraseña_maestra'] = contraseña
            flash(f'Inicio de sesión exitoso | Algoritmo: SHA-256 con 100,000 iteraciones y sal de 32 bytes | Longitud hash: 256 bits', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas', 'error')
    
    return render_template('inicio_sesion.html')

# Ruta dashboard
@app.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        flash('Debes iniciar sesión primero', 'error')
        return redirect(url_for('inicio_sesion'))
    
    # Obtenemos lista de servicios del usuario
    services = manager_contraseñas.listar_servicios(session['usuario'])
    return render_template('dashboard.html', 
                        usuario=session['usuario'], 
                        services=services)

# Ruta añadir contraseña
@app.route('/añadir_contraseña', methods=['POST'])
def añadir_contraseña(): 
    if 'usuario' not in session:
        return redirect(url_for('inicio_sesion'))
    
    servicio = request.form['servicio']
    contraseña = request.form['contraseña']
    correo = request.form['correo']  # Ahora es obligatorio
    
    # Verificamos campos vacíos
    if not servicio.strip() or not correo.strip():
        flash('Todos los campos son obligatorios', 'error')
        return redirect(url_for('dashboard'))
    
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, correo):
        flash('Formato de correo electrónico inválido', 'error')
        return redirect(url_for('dashboard'))
    
    resultado = manager_contraseñas.añadir_contraseña(
        session['usuario'], 
        servicio, 
        contraseña, 
        session['contraseña_maestra'],
        correo
    )
    
    if resultado:
        flash(f'Contraseña para {servicio} guardada correctamente | Algoritmo: Híbrido (AES-256 + RSA-2048) + HMAC-SHA256 + Firmado', 'success')
    else:
        flash(f'Ya existe una entrada para {servicio} con el correo {correo}', 'error')
    
    return redirect(url_for('dashboard'))

# Ruta obtener contraseña
@app.route('/obtener_contraseña/<servicio>/<correo>')
def obtener_contraseña(servicio, correo):
    if 'usuario' not in session:
        return jsonify({"error": "unauthorized", "message": "Sesión expirada"}), 401
    
    contraseña = manager_contraseñas.obtener_contraseña(
        session['usuario'], 
        servicio, 
        session['contraseña_maestra'],
        correo
    )
    
    if contraseña:
        flash(f"Contraseña descifrada | Algoritmo: Híbrido (AES-256 + RSA-2048) + HMAC-SHA256 + Firma comprobada", 'success')
        return jsonify({"contraseña": contraseña})
    else:
        return jsonify({"error": "Contraseña no encontrada"}), 404

# Ruta eliminar contraseña
@app.route('/eliminar_contraseña/<servicio>/<correo>', methods=['POST'])
def eliminar_contraseña(servicio, correo):
    if 'usuario' not in session:
        return redirect(url_for('inicio_sesion'))
    
    resultado = manager_contraseñas.eliminar_entrada(session['usuario'], servicio, correo)
    
    if resultado:
        flash(f'Contraseña para {servicio} eliminada', 'success')
    else:
        flash(f'Error eliminando contraseña para {servicio}', 'error')
    
    return redirect(url_for('dashboard'))

# Ruta editar contraseña
@app.route('/editar_contraseña/<servicio>/<correo>', methods=['GET', 'POST'])
def editar_contraseña(servicio, correo):
    if 'usuario' not in session:
        return redirect(url_for('inicio_sesion'))
    
    if request.method == 'GET':
        return render_template('editar_contraseña.html', 
                            servicio=servicio, 
                            correo=correo,
                            usuario=session['usuario'])
    
    elif request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        nuevo_correo = request.form['correo']

        # Verificamos campos vacíos
        if not nueva_contraseña.strip() or not nuevo_correo.strip():
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('dashboard'))
        
        # Validamos email
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, nuevo_correo):
            flash('Formato de correo electrónico inválido', 'error')
            return redirect(url_for('dashboard'))
        
        # Mismo correo
        if nuevo_correo == correo:
            resultado = manager_contraseñas.actualizar_contraseña(
                session['usuario'],
                servicio,
                nueva_contraseña,
                session['contraseña_maestra'],
                correo
            )
            if resultado:
                flash(f'Contraseña para {servicio} actualizada correctamente | Algoritmo: Híbrido (AES-256 + RSA-2048) + HMAC-SHA256 | Longitud clave: 256 bits', 'success')
            else:
                flash(f'Error actualizando contraseña para {servicio}', 'error')
        
        # Correo diferente
        else:
            # Verificamos si ya existe servicio+nuevo_correo
            if manager_contraseñas.entrada_existe(session['usuario'], servicio, nuevo_correo):
                flash(f'Ya existe un inicio de sesión para {servicio} con el correo {nuevo_correo}', 'error')
            else:
                # Eliminamos entrada antigua y crear nueva
                manager_contraseñas.eliminar_entrada(session['usuario'], servicio, correo)
                resultado = manager_contraseñas.añadir_contraseña(
                    session['usuario'],
                    servicio,
                    nueva_contraseña,
                    session['contraseña_maestra'],
                    nuevo_correo
                )
                if resultado:
                    flash(f'Inicio de sesión para {servicio} actualizado correctamente', 'success')
                else:
                    flash(f'Error actualizando inicio de sesión para {servicio}', 'error')
        
        return redirect(url_for('dashboard'))

# Ruta cerrar sesión
@app.route('/cerrar_sesion')
def cerrar_sesion():
    session.clear()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('index'))

# Para ejecutar, ejecutar este archivo python e ir a http://localhost:5000/
if __name__ == '__main__':
    app.run(debug=True, port=5000)
