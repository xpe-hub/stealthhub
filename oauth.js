/**
 * OAuth Authentication System - Bypass Supreme
 * Manejo seguro de Google, GitHub y Discord OAuth
 */

class OAuthManager {
    constructor() {
        this.config = null;
        this.isInitialized = false;
        this.init();
    }

    async init() {
        try {
            // Cargar configuración OAuth
            await this.loadConfig();
            this.setupEventListeners();
            this.checkAuthStatus();
            this.isInitialized = true;
        } catch (error) {
            console.error('Error inicializando OAuth:', error);
        }
    }

    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            this.config = await response.json();
            console.log('🔧 OAuth Config:', this.config);
        } catch (error) {
            console.error('Error cargando configuración OAuth:', error);
            this.config = {
                oauth_ready: false,
                providers: {
                    google: { available: false },
                    github: { available: false },
                    discord: { available: true }
                }
            };
        }
    }

    setupEventListeners() {
        // Configurar botones de OAuth
        const googleBtn = document.querySelector('[data-provider="google"]');
        const githubBtn = document.querySelector('[data-provider="github"]');
        const discordBtn = document.querySelector('[data-provider="discord"]');

        if (googleBtn) {
            googleBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.loginWithProvider('google');
            });
        }

        if (githubBtn) {
            githubBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.loginWithProvider('github');
            });
        }

        if (discordBtn) {
            discordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.loginWithProvider('discord');
            });
        }
    }

    async loginWithProvider(provider) {
        try {
            if (!this.config || !this.config.oauth_ready) {
                this.showError(`${provider} OAuth no está configurado. Contacta al administrador.`);
                return;
            }

            const providerConfig = this.config.providers[provider];
            if (!providerConfig.available) {
                this.showError(`${provider} OAuth no está disponible en este momento.`);
                return;
            }

            // Mostrar loading
            this.showLoading(`Iniciando autenticación con ${provider}...`);

            // Redirigir a OAuth
            window.location.href = providerConfig.url;

        } catch (error) {
            console.error(`Error OAuth ${provider}:`, error);
            this.showError(`Error iniciando autenticación con ${provider}`);
        }
    }

    async checkAuthStatus() {
        try {
            const response = await fetch('/api/auth/status');
            const data = await response.json();

            if (data.authenticated) {
                // Usuario ya autenticado, redirigir
                console.log('🔐 Usuario ya autenticado, redirigiendo...');
                setTimeout(() => {
                    window.location.href = 'index_ultimate.html';
                }, 2000);
            }
        } catch (error) {
            console.error('Error verificando estado de auth:', error);
        }
    }

    showLoading(message) {
        const loadingDiv = document.getElementById('oauthLoading') || this.createLoadingDiv();
        loadingDiv.style.display = 'block';
        loadingDiv.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
            ">
                <div style="
                    background: rgba(15, 15, 15, 0.95);
                    border: 2px solid #FF0080;
                    border-radius: 20px;
                    padding: 40px;
                    text-align: center;
                    color: white;
                    font-family: 'Rajdhani', sans-serif;
                ">
                    <div style="
                        width: 40px;
                        height: 40px;
                        border: 3px solid rgba(0, 255, 255, 0.3);
                        border-top: 3px solid #00FFFF;
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                        margin: 0 auto 20px;
                    "></div>
                    <p style="font-size: 1.2em; margin: 0;">${message}</p>
                </div>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    hideLoading() {
        const loadingDiv = document.getElementById('oauthLoading');
        if (loadingDiv) {
            loadingDiv.style.display = 'none';
        }
    }

    createLoadingDiv() {
        const loadingDiv = document.createElement('div');
        loadingDiv.id = 'oauthLoading';
        document.body.appendChild(loadingDiv);
        return loadingDiv;
    }

    showError(message) {
        this.hideLoading();
        
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #FF0080, #CC0066);
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            font-family: 'Rajdhani', sans-serif;
            font-weight: 600;
            z-index: 10001;
            box-shadow: 0 8px 32px rgba(255, 0, 128, 0.3);
            animation: slideInRight 0.5s ease-out;
        `;
        errorDiv.innerHTML = `
            <i class="fas fa-exclamation-triangle" style="margin-right: 10px;"></i>
            ${message}
            <button onclick="this.parentElement.remove()" style="
                background: none;
                border: none;
                color: white;
                margin-left: 15px;
                cursor: pointer;
                font-size: 1.2em;
            ">&times;</button>
        `;

        document.body.appendChild(errorDiv);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.remove();
            }
        }, 5000);
    }

    async logout() {
        try {
            const response = await fetch('/api/auth/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            
            if (data.success) {
                console.log('🔓 Logout exitoso');
                window.location.href = 'login.html';
            } else {
                throw new Error('Error en logout');
            }
        } catch (error) {
            console.error('Error en logout:', error);
            // Forzar logout local
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    }

    // Utility functions for checking authentication in other parts of the app
    async isAuthenticated() {
        try {
            const response = await fetch('/api/auth/status');
            const data = await response.json();
            return data.authenticated;
        } catch (error) {
            console.error('Error verificando autenticación:', error);
            return false;
        }
    }

    async getUserData() {
        try {
            const response = await fetch('/api/auth/status');
            const data = await response.json();
            return data.authenticated ? data.user_data : null;
        } catch (error) {
            console.error('Error obteniendo datos de usuario:', error);
            return null;
        }
    }

    // Update social buttons based on OAuth config
    updateSocialButtons() {
        if (!this.config) return;

        // Google button
        const googleBtn = document.querySelector('[data-provider="google"]');
        if (googleBtn) {
            if (this.config.providers.google.available) {
                googleBtn.style.opacity = '1';
                googleBtn.style.pointerEvents = 'auto';
                googleBtn.title = 'Iniciar sesión con Google';
            } else {
                googleBtn.style.opacity = '0.5';
                googleBtn.style.pointerEvents = 'none';
                googleBtn.title = 'Google OAuth no configurado';
            }
        }

        // GitHub button
        const githubBtn = document.querySelector('[data-provider="github"]');
        if (githubBtn) {
            if (this.config.providers.github.available) {
                githubBtn.style.opacity = '1';
                githubBtn.style.pointerEvents = 'auto';
                githubBtn.title = 'Iniciar sesión con GitHub';
            } else {
                githubBtn.style.opacity = '0.5';
                githubBtn.style.pointerEvents = 'none';
                githubBtn.title = 'GitHub OAuth no configurado';
            }
        }

        // Discord button (always available)
        const discordBtn = document.querySelector('[data-provider="discord"]');
        if (discordBtn) {
            discordBtn.title = 'Unirse a la comunidad Discord';
        }
    }
}

// Initialize OAuth manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.oauthManager = new OAuthManager();
});

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OAuthManager;
}