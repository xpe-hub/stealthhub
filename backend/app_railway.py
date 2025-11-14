 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StealthHub - Professional AI Platform with Google OAuth
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
from google.oauth2 import id_token
from google.auth.transport import requests
import requests as http_requests
import jwt
from functools import wraps

# ConfiguraciÃ³n de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ConfiguraciÃ³n de la aplicaciÃ³n
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'xpe-nettt-bypass-supreme-secret-key-2025')
CORS(app, supports_credentials=True)

# ConfiguraciÃ³n Google OAuth - SOLO desde variables de entorno
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

# Verificar que las credenciales estÃ©n configuradas
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    logger.error("Google OAuth credentials not configured!")
    logger.error("Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")

# Base de datos de usuarios (SQLite)
DATABASE = 'stealthhub_users.db'

def init_db():
    """Inicializa la base de datos de usuarios"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Crear tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT,
            google_id TEXT UNIQUE,
            profile_photo TEXT,
            bio TEXT DEFAULT '',
            experience_level TEXT DEFAULT 'beginner',
            categories TEXT DEFAULT '[]',
            badges TEXT DEFAULT '[]',
            google_auth BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Decorador para rutas protegidas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Sistema de IA Contextual
class StealthHubAI:
    def __init__(self):
        self.categories = {
            'reverse_engineering': {
                'name': 'Reverse Engineering',
                'description': 'AnÃ¡lisis y descomposiciÃ³n de software',
                'level_responses': {
                    'beginner': 'Como principiante en Reverse Engineering, te recomiendo empezar con herramientas bÃ¡sicas como IDA Free o x64dbg. Â¿En quÃ© sistema especÃ­fico necesitas ayuda?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar tÃ©cnicas como API hooking y memory patching. Â¿QuÃ© tipo de binario estÃ¡s analizando?',
                    'expert': 'Como experto, podemos profundizar en tÃ©cnicas avanzadas como packer detection, anti-debug bypass y malware analysis. Â¿Necesitas ayuda con bypass de protecciones?'
                }
            },
            'malware_analysis': {
                'name': 'Malware Analysis',
                'description': 'AnÃ¡lisis seguro de software malicioso',
                'level_responses': {
                    'beginner': 'Para anÃ¡lisis de malware seguro, siempre usa VMs aisladas. Â¿QuÃ© tipo de muestra tienes disponible?',
                    'intermediate': 'Como analista intermedio, puedes usar tÃ©cnicas como sandboxing y behavioral analysis. Â¿Necesitas ayuda con static o dynamic analysis?',
                    'expert': 'Como experto en malware, podemos trabajar con tÃ©cnicas avanzadas como memory forensics y network analysis. Â¿Es un sample encryptado?'
                }
            },
            'bypass_techniques': {
                'name': 'Bypass Techniques',
                'description': 'TÃ©cnicas de evasiÃ³n y bypass',
                'level_responses': {
                    'beginner': 'Para bypass bÃ¡sico, considera tÃ©cnicas como process hollowing y DLL injection. Â¿QuÃ© tipo de protecciÃ³n enfrentas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar tÃ©cnicas como API unhooking y EDR evasion. Â¿Necesitas bypass de AV o EDR?',
                    'expert': 'Como experto, podemos trabajar con tÃ©cnicas como process injection via parent PID, NtCreateProcessEx bypass. Â¿QuÃ© evasiÃ³n necesitas?'
                }
            },
            'cryptography': {
                'name': 'Cryptography',
                'description': 'AnÃ¡lisis criptogrÃ¡fico y implementaciÃ³n segura',
                'level_responses': {
                    'beginner': 'Para anÃ¡lisis criptogrÃ¡fico bÃ¡sico, enfÃ³cate en algoritmos comunes como XOR, AES bÃ¡sico. Â¿QuÃ© tipo de cifrado necesitas analizar?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar RSA, elliptic curve cryptography y implementaciones personalizadas. Â¿Tienes una key especÃ­fica?',
                    'expert': 'Como experto, podemos trabajar con cryptanalysis avanzado, side-channel attacks y quantum-resistant algorithms. Â¿Es una implementaciÃ³n custom?'
                }
            },
            'network_security': {
                'name': 'Network Security',
                'description': 'Seguridad de redes y anÃ¡lisis de trÃ¡fico',
                'level_responses': {
                    'beginner': 'Para anÃ¡lisis de red bÃ¡sico, usa Wireshark y analiza protocolos comunes. Â¿QuÃ© tipo de trÃ¡fico necesitas revisar?',
                    'intermediate': 'Como analista intermedio, puedes trabajar con packet crafting y network evasion. Â¿Necesitas anÃ¡lisis de malware networking?',
                    'expert': 'Como experto, podemos explorar advanced persistent threats, DNS exfiltration y network lateral movement. Â¿QuÃ© protocolo te interesa?'
                }
            },
            'mobile_security': {
                'name': 'Mobile Security',
                'description': 'Seguridad en dispositivos mÃ³viles',
                'level_responses': {
                    'beginner': 'Para mÃ³vil bÃ¡sico, aprende sobre APK analysis y static/dynamic analysis. Â¿QuÃ© OS estÃ¡s analizando?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar jailbreaking/rooting y certificate pinning bypass. Â¿Es iOS o Android?',
                    'expert': 'Como experto, podemos trabajar con iOS kernel exploitation, Android security models bypass. Â¿Necesitas anÃ¡lisis de privacidad?'
                }
            },
            'web_security': {
                'name': 'Web Security',
                'description': 'Seguridad en aplicaciones web',
                'level_responses': {
                    'beginner': 'Para web bÃ¡sico, enfÃ³cate en SQL injection, XSS y CSRF. Â¿QuÃ© tecnologÃ­a web usas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar CSP bypass, SSRF y API security. Â¿Es una SPA o aplicaciÃ³n tradicional?',
                    'expert': 'Como experto, podemos trabajar con advanced deserialization attacks, prototype pollution y cloud security. Â¿QuÃ© framework usas?'
                }
            },
            'system_security': {
                'name': 'System Security',
                'description': 'Seguridad a nivel de sistema operativo',
                'level_responses': {
                    'beginner': 'Para sistema bÃ¡sico, aprende sobre user permissions, service hardening y process isolation. Â¿QuÃ© SO usas?',
                    'intermediate': 'Como desarrollador intermedio, puedes explorar kernel debugging y driver security. Â¿Necesitas help con privilege escalation?',
                    'expert': 'Como experto, podemos trabajar con kernel exploitation, hypervisor attacks y hardware security. Â¿QuÃ© arquitectura target?'
                }
            }
        }
        
        self.badges = {
            'first_login': 'Welcome Explorer',
            'category_explorer': 'Category Explorer',
            'security_newbie': 'Security Newbie',
            'code_analyzer': 'Code Analyzer',
            'malware_hunter': 'Malware Hunter',
            'bypass_master': 'Bypass Master',
            'crypto_expert': 'Crypto Expert',
            'network_guardian': 'Network Guardian',
            'mobile_defender': 'Mobile Defender',
            'web_warrior': 'Web Warrior',
            'system_sentinel': 'System Sentinel',
            'researcher': 'Security Researcher',
            'mentor': 'Community Mentor',
            'innovator': 'Security Innovator'
        }
    
    def get_contextual_response(self, category, level, user_name):
        """Genera respuesta contextual basada en categorÃ­a y nivel"""
        if category in self.categories and level in self.categories[category]['level_responses']:
            base_response = self.categories[category]['level_responses'][level]
            return f"ðŸ” **{user_name}**, {base_response}\n\nðŸ’¡ **CategorÃ­a seleccionada:** {self.categories[category]['name']}\nðŸŽ¯ **Tu nivel:** {level.title()}\n\nÂ¿En quÃ© aspecto especÃ­fico te gustarÃ­a profundizar?"
        return "Â¡Hola! Â¿En quÃ© Ã¡rea de la seguridad informÃ¡tica necesitas ayuda hoy? ðŸš€"

ai_system = StealthHubAI()

@app.route('/')
def index():
    """PÃ¡gina principal"""
    user = None
    if 'user_id' in session:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            user = {
                'id': user_data[0],
                'email': user_data[1],
                'name': user_data[2],
                'profile_photo': user_data[5] or '',
                'bio': user_data[6] or '',
                'experience_level': user_data[7] or 'beginner',
                'badges': json.loads(user_data[9]) if user_data[9] else []
            }
    
    return render_template('index.html', user=user, categories=ai_system.categories, badges=ai_system.badges)

@app.route('/auth/google')
def google_login():
    """Inicia el flujo de autenticaciÃ³n con Google"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth not configured'}), 500
    
    import urllib.parse
    
    google_auth_url = "https://accounts.google.com/o/oauth2/auth"
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': f"{request.url_root}auth/google/callback",
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent'
    }
    
    auth_url = f"{google_auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@app.route('/auth/google/callback')
def google_callback():
    """Callback de Google OAuth"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth not configured'}), 500
        
    try:
        code = request.args.get('code')
        
        # Intercambiar cÃ³digo por token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': f"{request.url_root}auth/google/callback",
            'grant_type': 'authorization_code'
        }
        
        token_response = http_requests.post(token_url, data=data)
        token_data = token_response.json()
        
        if 'error' in token_data:
            logger.error(f"Error getting tokens: {token_data}")
            return redirect(url_for('index'))
        
        # Obtener informaciÃ³n del usuario
        userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {'Authorization': f"Bearer {token_data['access_token']}"}
        userinfo_response = http_requests.get(userinfo_url, headers=headers)
        user_info = userinfo_response.json()
        
        # Buscar o crear usuario en la base de datos
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar usuario por Google ID
        cursor.execute("SELECT id FROM users WHERE google_id = ?", (user_info['id'],))
        existing_user = cursor.fetchone()
        
        if existing_user:
            # Actualizar Ãºltimo login
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", (user_info['id'],))
            user_id = existing_user[0]
        else:
            # Crear nuevo usuario
            cursor.execute('''
                INSERT INTO users (email, name, google_id, google_auth, last_login)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_info['email'], user_info['name'], user_info['id'], True))
            user_id = cursor.lastrowid
            
            # Asignar badge de bienvenida
            cursor.execute("SELECT badges FROM users WHERE id = ?", (user_id,))
            badges_data = cursor.fetchone()
            badges = json.loads(badges_data[0]) if badges_data[0] else []
            if 'first_login' not in badges:
                badges.append('first_login')
                cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(badges), user_id))
        
        conn.commit()
        conn.close()
        
        # Configurar sesiÃ³n
        session['user_id'] = user_id
        session['user_name'] = user_info['name']
        session['user_email'] = user_info['email']
        
        logger.info(f"Google OAuth login successful for: {user_info['email']}")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        return redirect(url_for('index'))

@app.route('/auth/register', methods=['POST'])
def register():
    """Registro tradicional de usuario"""
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([name, email, password]):
            return jsonify({'success': False, 'error': 'Todos los campos son requeridos'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'El email ya estÃ¡ registrado'})
        
        # Crear nuevo usuario
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (name, email, password_hash, google_auth, last_login)
            VALUES (?, ?, ?, FALSE, CURRENT_TIMESTAMP)
        ''', (name, email, password_hash))
        
        user_id = cursor.lastrowid
        
        # Asignar badge de bienvenida
        cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(['first_login']), user_id))
        
        conn.commit()
        conn.close()
        
        # Configurar sesiÃ³n
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_email'] = email
        
        return jsonify({'success': True, 'message': 'Registro exitoso'})
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'error': 'Error en el registro'})

@app.route('/auth/login', methods=['POST'])
def login():
    """Login tradicional"""
    try:
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([email, password]):
            return jsonify({'success': False, 'error': 'Email y contraseÃ±a requeridos'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE email = ? AND google_auth = FALSE", (email,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[1], password):
            session['user_id'] = user_data[0]
            session['user_email'] = email
            
            # Actualizar Ãºltimo login
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_data[0],))
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'message': 'Login exitoso'})
        else:
            return jsonify({'success': False, 'error': 'Credenciales invÃ¡lidas'})
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Error en el login'})

@app.route('/auth/logout')
def logout():
    """Cerrar sesiÃ³n"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard del usuario"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()
    
    if not user_data:
        return redirect(url_for('index'))
    
    user = {
        'id': user_data[0],
        'email': user_data[1],
        'name': user_data[2],
        'profile_photo': user_data[5] or '',
        'bio': user_data[6] or '',
        'experience_level': user_data[7] or 'beginner',
        'categories': json.loads(user_data[8]) if user_data[8] else [],
        'badges': json.loads(user_data[9]) if user_data[9] else []
    }
    
    return render_template('dashboard.html', user=user, categories=ai_system.categories, badges=ai_system.badges)

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    """API de chat con IA contextual"""
    try:
        data = request.get_json()
        category = data.get('category', 'reverse_engineering')
        message = data.get('message', '')
        
        # Obtener nivel del usuario
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT name, experience_level FROM users WHERE id = ?", (session['user_id'],))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            user_name, level = user_data
            response = ai_system.get_contextual_response(category, level, user_name)
            
            # Actualizar estadÃ­sticas del usuario
            update_user_stats(category)
            
            return jsonify({
                'success': True,
                'response': response,
                'category': category,
                'level': level
            })
        else:
            return jsonify({'success': False, 'error': 'Usuario no encontrado'})
            
    except Exception as e:
        logger.error(f"Chat API error: {e}")
        return jsonify({'success': False, 'error': 'Error en el chat'})

def update_user_stats(category):
    """Actualiza estadÃ­sticas del usuario basado en interacciones"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Obtener categorÃ­as actuales del usuario
        cursor.execute("SELECT categories FROM users WHERE id = ?", (session['user_id'],))
        categories_data = cursor.fetchone()
        categories = json.loads(categories_data[0]) if categories_data and categories_data[0] else []
        
        # Agregar nueva categorÃ­a si no existe
        if category not in categories:
            categories.append(category)
            cursor.execute("UPDATE users SET categories = ? WHERE id = ?", (json.dumps(categories), session['user_id']))
            
            # Asignar badge si el usuario explora mÃºltiples categorÃ­as
            if len(categories) >= 3:
                cursor.execute("SELECT badges FROM users WHERE id = ?", (session['user_id'],))
                badges_data = cursor.fetchone()
                badges = json.loads(badges_data[0]) if badges_data and badges_data[0] else []
                if 'category_explorer' not in badges:
                    badges.append('category_explorer')
                    cursor.execute("UPDATE users SET badges = ? WHERE id = ?", (json.dumps(badges), session['user_id']))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Update stats error: {e}")

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Actualizar perfil de usuario"""
    try:
        data = request.get_json()
        bio = data.get('bio', '')
        experience_level = data.get('experience_level', 'beginner')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Asignar badge basado en nivel de experiencia
        cursor.execute("SELECT badges FROM users WHERE id = ?", (session['user_id'],))
        badges_data = cursor.fetchone()
        badges = json.loads(badges_data[0]) if badges_data and badges_data[0] else []
        
        level_badges = {
            'beginner': 'security_newbie',
            'intermediate': 'code_analyzer',
            'expert': 'researcher'
        }
        
        if experience_level in level_badges and level_badges[experience_level] not in badges:
            badges.append(level_badges[experience_level])
        
        cursor.execute('''
            UPDATE users 
            SET bio = ?, experience_level = ?, badges = ?
            WHERE id = ?
        ''', (bio, experience_level, json.dumps(badges), session['user_id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Perfil actualizado'})
        
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        return jsonify({'success': False, 'error': 'Error actualizando perfil'})

if __name__ == '__main__':
    # Inicializar base de datos
    init_db()
    
    # ConfiguraciÃ³n para desarrollo
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    logger.info(f"Iniciando StealthHub en puerto {port}")
    if GOOGLE_CLIENT_ID:
        logger.info("Google OAuth configurado correctamente")
    else:
        logger.warning("Google OAuth NO configurado - falta GOOGLE_CLIENT_ID")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
