#!/usr/bin/env python3
# -*- codificación: utf-8 -*-
""
StealthHub: plataforma profesional de IA con Google OAuth
""

importar sistema operativo
importar json
Registro de importación
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
importar sqlite3
importar hashlib
from google.oauth2 import id_token
from google.auth.transport import requests
importar solicitudes como solicitudes_http
importar jwt
from functools import wraps

# Configuración de registro
logging.basicConfig(level=logging.INFO)
registrador = registro.obtenerRegistrador(__nombre__)

# Configuración de la aplicación
aplicación = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'xpe-nettt-bypass-supreme-secret-key-2025')
CORS(app, supports_credentials=True)

# Configuración Google OAuth - SOLO desde variables de entorno
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

# Verificar que las credenciales están configuradas
si no es GOOGLE_CLIENT_ID o no es GOOGLE_CLIENT_SECRET:
    logger.error("¡Credenciales OAuth de Google no configuradas!")
    logger.error("Por favor, configure las variables de entorno GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET")

# Base de datos de usuarios (SQLite)
BASE DE DATOS = 'stealthhub_users.db'

def init_db():
    """Inicializa la base de datos de usuarios"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Crear tabla de usuarios
    cursor.execute('''
        CREAR TABLA SI NO EXISTE usuarios (
            id INTEGER CLAVE PRIMARIA AUTOINCREMENTE,
            correo electrónico TEXTO ÚNICO NO NULO,
            nombre TEXTO NO NULO,
            texto de hash de contraseña,
            google_id TEXTO ÚNICO,
            foto de perfil TEXTO,
            bio TEXTO PREDETERMINADO '',
            nivel_experiencia TEXTO PREDETERMINADO 'principiante',
            categorías TEXTO PREDETERMINADO '[]',
            insignias TEXTO PREDETERMINADO '[]',
            google_auth BOOLEAN DEFAULT FALSE,
            creado_en MARCA DE TIEMPO PREDETERMINADA MARCA_DE_TIEMPO_ACTUAL,
            última_seguimiento MARCA DE TIEMPO
        )
    ''')
    
    conn.commit()
    conn.close()

# Decorador para rutas protegidas
def login_required(f):
    @wraps(f)
    def función_decorada(*args, **kwargs):
        Si 'user_id' no está en la sesión:
            devolver redireccionar(url_para('index'))
        devolver f(*args, **kwargs)
    Devuelve la función decorada

# Sistema de IA Contextual
Clase StealthHubAI:
    def __init__(self):
        self.categories = {
            'ingeniería_inversa': {
                'nombre': 'Ingeniería inversa',
                'description': 'Análisis y descomposición de software',
                'level_responses': {
                    'beginner': 'Como principio en ingeniería inversa, te recomiendo empezar con herramientas básicas como IDA Free o x64dbg. ¿En qué sistema específico necesitas ayuda?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar técnicas como API Hooking y parches de memoria. ¿Qué tipo de binario estás analizando?',
                    'expert': 'Como experto, podemos profundizar en técnicas avanzadas como detección de empaquetadores, bypass anti-depuración y análisis de malware. ¿Necesitas ayuda con bypass de protecciones?'
                }
            },
            'malware_analysis': {
                'nombre': 'Análisis de malware',
                'description': 'Análisis seguro de software malicioso',
                'level_responses': {
                    'beginner': 'Para análisis de malware seguro, siempre usa VM aisladas. ¿Qué tipo de muestra tienes disponible?',
                    'intermediate': 'Como analista intermedio, puedes usar técnicas como sandboxing y análisis de comportamiento. ¿Necesitas ayuda con análisis estático o dinámico?',
                    'expert': 'Como experto en malware, podemos trabajar con técnicas avanzadas como memoria forense y análisis de redes. ¿Es una muestra cifrada?
                }
            },
            'técnicas_de_elusión': {
                'nombre': 'Técnicas de derivación',
                'description': 'Técnicas de evasión y bypass',
                'level_responses': {
                    'beginner': 'Para bypass básico, considera técnicas como Process Hollowing e inyección de DLL. ¿Qué tipo de protección enfrentas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar técnicas como API unhooking y EDR evasion. ¿Necesitas bypass de AV o EDR?',
                    'expert': 'Como experto, podemos trabajar con técnicas como inyección de procesos vía PID principal, bypass NtCreateProcessEx. ¿Qué evasión necesitas?'
                }
            },
            'criptografía': {
                'nombre': 'Criptografía',
                'description': 'Análisis criptográfico e implementación segura',
                'level_responses': {
                    'beginner': 'Para análisis criptográfico básico, enfóquese en algoritmos comunes como XOR, AES básico. ¿Qué tipo de cifrado necesitas analizar?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar RSA, criptografía de curva elíptica e implementaciones personalizadas. ¿Tienes una clave específica?',
                    'expert': 'Como experto, podemos trabajar con criptoanálisis avanzado, ataques de canal lateral y algoritmos resistentes a lo cuántico. ¿Es una implementación personalizada?'
                }
            },
            'seguridad_de_red': {
                'nombre': 'Seguridad de red',
                'description': 'Seguridad de redes y análisis de tráfico',
                'level_responses': {
                    'beginner': 'Para análisis de red básico, usa Wireshark y analiza protocolos comunes. ¿Qué tipo de tráfico necesitas revisar?',
                    'intermediate': 'Como analista intermedio, puedes trabajar con paquete crafting y network evasion. ¿Necesitas análisis de redes de malware?',
                    'experto': 'Como experto, podemos explorar amenazas persistentes avanzadas, exfiltración de DNS y movimiento lateral de red. ¿Qué protocolo te interesa?'
                }
            },
            'seguridad_móvil': {
                'nombre': 'Seguridad móvil',
                'description': 'Seguridad en dispositivos móviles',
                'level_responses': {
                    'beginner': 'Para móvil básico, aprende sobre análisis APK y análisis estático/dinámico. ¿Qué OS estás analizando?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar jailbreak/rooting y bypass de fijación de certificados. ¿Es iOS o Android?',
                    'expert': 'Como experto, podemos trabajar con la explotación del kernel de iOS, evitando los modelos de seguridad de Android. ¿Necesitas análisis de privacidad?'
                }
            },
            'seguridad_web': {
                'nombre': 'Seguridad Web',
                'description': 'Seguridad en aplicaciones web',
                'level_responses': {
                    'beginner': 'Para web básica, enfocate en inyección SQL, XSS y CSRF. ¿Qué tecnología web usas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar la seguridad de CSP, SSRF y API. ¿Es una SPA o aplicación tradicional?',
                    'expert': 'Como experto, podemos trabajar con ataques avanzados de deserialización, contaminación de prototipos y seguridad en la nube. ¿Qué marco usas?
                }
            },
            'seguridad_del_sistema': {
                'nombre': 'Seguridad del sistema',
                'description': 'Seguridad a nivel de sistema operativo',
                'level_responses': {
                    'beginner': 'Para sistema básico, aprende sobre permisos de usuario, refuerzo de servicios y aislamiento de procesos. Â¿QÃ© SO usas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar la depuración del kernel y la seguridad del controlador. ¿Necesitas ayuda con la escalada de privilegios?',
                    'expert': 'Como experto, podemos trabajar con explotación del kernel, ataques de hipervisor y seguridad del hardware. ¿Qué arquitectura objetivo?
                }
            }
        }
        
        self.insignias = {
            'primer_inicio_de_sesión': 'Bienvenido Explorador',
            'category_explorer': 'Explorador de categorías',
            'security_newbie': 'Principiante en seguridad',
            'code_analyzer': 'Analizador de código',
            'malware_hunter': 'Cazador de malware',
            'bypass_master': 'Bypass Master',
            'crypto_expert': 'Experto en criptomonedas',
            'network_guardian': 'Guardián de la red',
            'mobile_defender': 'Defensor móvil',
            'web_warrior': 'Guerrero web',
            'system_sentinel': 'Centinela del sistema',
            'investigador': 'Investigador de seguridad',
            'mentor': 'Mentor comunitario',
            'innovador': 'Innovador en seguridad'
        }
    
    def obtener_respuesta_contextual(self, categoría, nivel, nombre_de_usuario):
        """Genera respuesta contextual basada en categoría y nivel"""
        Si category está en self.categories y level está en self.category[category]['level_responses']:
            respuesta_base = self.categories[category]['level_responses'][level]
            return f"ðŸ” **{user_name}**, {base_response}\n\nðŸ'¡ **Categoría seleccionada:** {self.categories[category]['name']}\nðŸŽ¯ **Tu nivel:** {level.title()}\n\nÂ¿En qué aspecto específico te gustaría profundizar?"
        return "¡Hola! ¿En qué área de la seguridad informática necesitas ayuda hoy? ðŸš€"

sistema_ai = StealthHubAI()

@app.route('/')
def índice():
    """Página principal"""
    usuario = Ninguno
    Si 'user_id' está en la sesión:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        datos_usuario = cursor.fetchone()
        conn.close()
        
        si user_data:
            usuario = {
                'id': user_data[0],
                'correo electrónico': datos_de_usuario[1],
                'nombre': datos_de_usuario[2],
                'foto_de_perfil': user_data[5] o '',
                'bio': user_data[6] o '',
                'nivel_de_experiencia': user_data[7] o 'principiante',
                'insignias': json.loads(user_data[9]) si user_data[9] else []
            }
    
    return render_template('index.html', user=user, categories=ai_system.categories, badges=ai_system.badges)

@app.route('/auth/google')
def google_login():
    """Inicia el flujo de autenticación con Google"""
    si no es GOOGLE_CLIENT_ID o no es GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth no está configurado'}), 500
    
    importar urllib.parse
    
    google_auth_url = "https://accounts.google.com/o/oauth2/auth"
    parámetros = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': f"{request.url_root}auth/google/callback",
        'tipo_respuesta': 'código',
        'alcance': 'perfil de correo electrónico de OpenID',
        'access_type': 'offline',
        'prompt': 'consentimiento'
    }
    
    auth_url = f"{google_auth_url}?{urllib.parse.urlencode(params)}"
    devolver redireccionar(url_autenticación)

@app.route('/auth/google/callback')
def google_callback():
    """Callback de Google OAuth"""
    si no es GOOGLE_CLIENT_ID o no es GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth no está configurado'}), 500
        
    intentar:
        código = solicitud.args.get('código')
        
        # Intercambiar código por token
        token_url = "https://oauth2.googleapis.com/token"
        datos = {
            'código': código,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': f"{request.url_root}auth/google/callback",
            'grant_type': 'authorization_code'
        }
        
        token_respuesta = http_requests.post(token_url, data=data)
        datos_token = respuesta_token.json()
        
        Si hay un 'error' en token_data:
            logger.error(f"Error al obtener los tokens: {token_data}")
            devolver redireccionar(url_para('index'))
        
        # Obtener información del usuario
        userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        encabezados = {'Autorización': f"Portador {token_data['access_token']}"}
        respuesta_información_usuario = solicitudes_http.get(url_información_usuario, encabezados=encabezados)
        información_usuario = respuesta_información_usuario.json()
        
        # Buscar o crear usuario en la base de datos
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar usuario por ID de Google
        cursor.execute("SELECT id FROM users WHERE google_id = ?", (user_info['id'],))
        usuario_existente = cursor.fetchone()
        
        si existe el usuario:
            # Actualizar último login
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", (user_info['id'],))
            id_usuario = usuario_existente[0]
        demás:
            # Crear nuevo usuario
            cursor.execute('''
                INSERT INTO users (email, name, google_id, google_auth, last_login)
                VALORES (?, ?, ?, ?, MARCA_DE_TIEMPO_ACTUAL)
            ''', (user_info['email'], user_info['name'], user_info['id'], True))
            id_usuario = cursor.lastrowid
            
            # Asignar insignia de bienvenida
            cursor.execute("SELECT badges FROM users WHERE id = ?", (user_id,))
            datos_insignias = cursor.fetchone()
            insignias = json.loads(datos_insignias[0]) si datos_insignias[0] sino []
            Si 'first_login' no está en las insignias:
                insignias.append('primer_inicio_de_sesión')
                cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(badges), user_id))
        
        conn.commit()
        conn.close()
        
        # Configurar sesión
        sesión['user_id'] = user_id
        sesión['nombre_usuario'] = información_usuario['nombre']
        sesión['correo_usuario'] = información_usuario['correo_usuario']
        
        logger.info(f"Inicio de sesión de Google OAuth exitoso para: {user_info['email']}")
        devolver redireccionar(url_para('panel de control'))
        
    excepto Excepción como e:
        logger.error(f"Error de OAuth de Google: {e}")
        devolver redireccionar(url_para('index'))

@app.route('/auth/register', methods=['POST'])
def registrar():
    """Registro tradicional de usuario"""
    intentar:
        nombre = solicitud.formulario.obtener('nombre')
        correo electrónico = solicitud.formulario.obtener('correo electrónico')
        contraseña = solicitud.formulario.obtener('contraseña')
        
        Si no todos([nombre, correo electrónico, contraseña]):
            return jsonify({'éxito': False, 'error': 'Todos los campos son requeridos'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar si el correo electrónico ya existe
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        si cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'El email ya está registrado'})
        
        # Crear nuevo usuario
        contraseña_hash = generar_contraseña_hash(contraseña)
        cursor.execute('''
            INSERT INTO users (name, email, password_hash, google_auth, last_login)
            VALORES (?, ?, ?, FALSO, MARCA_DE_TIEMPO_ACTUAL)
        ''', (nombre, correo electrónico, hash de contraseña))
        
        id_usuario = cursor.lastrowid
        
        # Asignar insignia de bienvenida
        cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(['first_login']), user_id))
        
        conn.commit()
        conn.close()
        
        # Configurar sesión
        sesión['user_id'] = user_id
        sesión['nombre_de_usuario'] = nombre
        sesión['user_email'] = correo electrónico
        
        return jsonify({'success': True, 'message': 'Registro exitoso'})
        
    excepto Excepción como e:
        logger.error(f"Error de registro: {e}")
        return jsonify({'éxito': False, 'error': 'Error en el registro'})

@app.route('/auth/login', methods=['POST'])
def iniciar sesión():
    """Inicio de sesión tradicional"""
    intentar:
        correo electrónico = solicitud.formulario.obtener('correo electrónico')
        contraseña = solicitud.formulario.obtener('contraseña')
        
        Si no todos([correo electrónico, contraseña]):
            return jsonify({'success': False, 'error': 'Email y contraseña requerida'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE email = ? AND google_auth = FALSE", (email,))
        datos_usuario = cursor.fetchone()
        conn.close()
        
        si user_data y check_password_hash(user_data[1], password):
            sesión['user_id'] = user_data[0]
            sesión['user_email'] = correo electrónico
            
            # Actualizar último login
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_data[0],))
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'message': 'Inicio de sesión exitoso'})
        demás:
            return jsonify({'éxito': False, 'error': 'Credenciales inválidas'})
            
    excepto Excepción como e:
        logger.error(f"Error de inicio de sesión: {e}")
        return jsonify({'success': False, 'error': 'Error al iniciar sesión'})

@app.route('/auth/logout')
def logout():
    """Cerrar sesión"""
    sesión.limpiar()
    devolver redireccionar(url_para('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard del usuario"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    datos_usuario = cursor.fetchone()
    conn.close()
    
    si no hay datos de usuario:
        devolver redireccionar(url_para('index'))
    
    usuario = {
        'id': user_data[0],
        'correo electrónico': datos_de_usuario[1],
        'nombre': datos_de_usuario[2],
        'foto_de_perfil': user_data[5] o '',
        'bio': user_data[6] o '',
        'nivel_de_experiencia': user_data[7] o 'principiante',
        'categories': json.loads(user_data[8]) if user_data[8] else [],
        'insignias': json.loads(user_data[9]) si user_data[9] else []
    }
    
    return render_template('dashboard.html', user=user, categories=ai_system.categories, badges=ai_system.badges)

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    """API de chat con IA contextual"""
    intentar:
        datos = solicitud.obtener_json()
        categoría = datos.obtener('categoría', 'ingeniería_inversa')
        mensaje = datos.obtener('mensaje', '')
        
        # 3 nivel del usuario
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT name, experience_level FROM users WHERE id = ?", (session['user_id'],))
        datos_usuario = cursor.fetchone()
        conn.close()
        
        si user_data:
            nombre_usuario, nivel = datos_usuario
            respuesta = ai_system.get_contextual_response(categoría, nivel, nombre_de_usuario)
            
            # Actualizar estadísticas del usuario
            actualizar_estadísticas_de_usuario(categoría)
            
            return jsonify({
                'éxito': Cierto,
                'respuesta': respuesta,
                'categoría': categoría,
                'nivel': nivel
            })
        demás:
            return jsonify({'éxito': False, 'error': 'Usuario no encontrado'})
            
    excepto Excepción como e:
        logger.error(f"Error de la API de chat: {e}")
        return jsonify({'success': False, 'error': 'Error en el chat'})

def actualizar_estadísticas_usuario(categoría):
    """Actualiza estadísticas del usuario basadas en interacciones"""
    intentar:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Obtener categorías actuales del usuario
        cursor.execute("SELECT categories FROM users WHERE id = ?", (session['user_id'],))
        datos_categorías = cursor.fetchone()
        categorías = json.loads(categories_data[0]) si categorías_data y categorías_data[0] sino []
        
        # Agregar nueva categoría si no existe
        Si la categoría no está en las categorías:
            categorías.append(categoría)
            cursor.execute("UPDATE users SET categories = ? WHERE id = ?", (json.dumps(categories), session['user_id']))
            
            # Asignar insignia si el usuario explora múltiples categorías
            Si la longitud de categorías es mayor o igual a 3:
                cursor.execute("SELECT badges FROM users WHERE id = ?", (session['user_id'],))
                datos_insignias = cursor.fetchone()
                insignias = json.loads(datos_insignias[0]) si datos_insignias y datos_insignias[0] sino []
                Si 'category_explorer' no está en las insignias:
                    insignias.append('explorador_de_categorías')
                    cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(badges), session['user_id']))
        
        conn.commit()
        conn.close()
        
    excepto Excepción como e:
        logger.error(f"Error al actualizar las estadísticas: {e}")

@app.route('/api/update_profile', methods=['POST'])
@login_required
def actualizar_perfil():
    """Actualizar perfil de usuario"""
    intentar:
        datos = solicitud.obtener_json()
        bio = data.get('bio', '')
        nivel_experiencia = datos.obtener('nivel_experiencia', 'principiante')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Asignar insignia basado en nivel de experiencia
        cursor.execute("SELECT badges FROM users WHERE id = ?", (session['user_id'],))
        datos_insignias = cursor.fetchone()
        insignias = json.loads(datos_insignias[0]) si datos_insignias y datos_insignias[0] sino []
        
        insignias_de_nivel = {
            'principiante': 'novato en seguridad',
            'intermedio': 'analista_de_código',
            'experto': 'investigador'
        }
        
        Si experience_level está en level_badges y level_badges[experience_level] no está en badges:
            insignias.append(insignias_de_nivel[nivel_de_experiencia])
        
        cursor.execute('''
            ACTUALIZAR usuarios
            ESTABLECER bio = ?, nivel_experiencia = ?, insignias = ?
            DONDE id = ?
        ''', (bio, experience_level, json.dumps(badges), session['user_id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'éxito': Verdadero, 'mensaje': 'Perfil actualizado'})
        
    excepto Excepción como e:
        logger.error(f"Error al actualizar el perfil: {e}")
        return jsonify({'éxito': False, 'error': 'Error actualizando perfil'})

Si __name__ == '__main__':
    # Inicializar base de datos
    inicializar_base_de_datos()
    
    # Configuración para desarrollo
    puerto = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    logger.info(f"Iniciando StealthHub en puerto {puerto}")
    si GOOGLE_CLIENT_ID:
        logger.info("Google OAuth configurado correctamente")
    demás:
        logger.warning("Google OAuth NO configurado - falta GOOGLE_CLIENT_ID")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
