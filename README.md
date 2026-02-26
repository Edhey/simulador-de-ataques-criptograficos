# 🔐 Simulador de Ataques Criptográficos

Una aplicación interactiva construida con **Streamlit** para explorar y comprender vulnerabilidades criptográficas, desde los cifrados clásicos hasta los sistemas modernos de cifrado.

## 📋 Descripción

Este proyecto es el **Proyecto Final** de la *Microcredencial "Criptografía y Seguridad Digital"* de la **Universidad de La Laguna (ULL)**.

Desmitifica los ataques criptográficos mediante simulación práctica y visualización interactiva, implementando la lógica matemática y estadística desde cero en Python.

### 🎯 Objetivo

Entender **cómo y por qué fallan los sistemas criptográficos**, no porque las matemáticas estén rotas, sino por:

- **Debilidades estadísticas** en algoritmos clásicos
- **Errores de implementación** en sistemas modernos
- **Fugas de información** (ej: Padding Oracle, nonce reutilizado)

## ✨ Características Principales

### 🏛️ Fase 1: Cifrados Clásicos

- **Cifrado César**: Análisis de frecuencia y recuperación de clave
- **Cifrado Vigenère**: Índice de Coincidencia (IC) + Algoritmo Kasiski para encontrar longitud de clave
- Visualizaciones interactivas de patrones estadísticos

### 💣 Fase 2: Ataques Modernos

- **Padding Oracle Attack**: Explotación de errores en AES-CBC
- **Ataque por Nonce Reutilizado**: Vulnerabilidad en AES-GCM
- Análisis paso a paso de cómo se recuperan mensajes cifrados

## 🗂️ Estructura del Proyecto

```
simulador-de-ataques-criptograficos/
├── streamlit_app.py                 # Punto de entrada - Configuración de navegación
├── utils.py                         # Funciones criptográficas y utilidades
├── requirements.txt                 # Dependencias del proyecto
├── views/                           # Páginas de la aplicación
│   ├── intro.py                     # Página principal y contexto
│   ├── clasicos-monoalfabetico.py   # Simulador de cifrado César
│   ├── clasicos-polialfabetico.py   # Simulador de cifrado Vigenère
│   └── modernos.py                  # Ataques a cifrados modernos (AES)
└── quijote.txt                      # Texto de ejemplo para simulaciones
```

## 🚀 Instalación y Uso

### Requisitos

- Python 3.8 o superior
- pip (gestor de paquetes Python)

### Pasos de Instalación

1. **Instalar las dependencias**

   ```bash
   pip install -r requirements.txt
   ```

2. **Ejecutar la aplicación**

   ```bash
   streamlit run streamlit_app.py
   ```

3. **Acceder a la aplicación**
   - Abre tu navegador en `http://localhost:8501`

## 📦 Dependencias

- **streamlit**: Framework para crear aplicaciones web interactivas
- **pycryptodome**: Funciones criptográficas (AES, padding, etc.)
- Librerías estándar: collections, string, random, unicodedata

Ver [requirements.txt](requirements.txt) para la lista completa.

## 📚 Contenido por Sección

### 🏠 Introducción

- Contexto del proyecto y motivación
- Cronología de ataques criptográficos
- Explicación del desafío y solución

### 🏛️ Cifrados Clásicos - Monoalfabético (César)

- Simulador de encriptación César
- Análisis de frecuencia de caracteres
- Ataque por fuerza bruta mejorada

### 📊 Análisis - Cipher Vigenère (Polialfabético)

- Cálculo del Índice de Coincidencia (IC)
- Algoritmo Kasiski para determinar longitud de clave
- Recuperación progresiva de la clave

### 💣 Ataques Modernos

- **Padding Oracle Attack**: Explotar errores de padding en AES-CBC
- **Ataque por Nonce Reutilizado**: Vulnerabilidad en AES-GCM con IVs repetidos

## 👤 Autor

**Himar Edhey Hernández Alonso**  
*Proyecto Final - Microcredencial Criptografía y Seguridad Digital*  
*Universidad de La Laguna (ULL)*

## 📄 Licencia

Este proyecto se distribuye bajo la licencia [Apache License 2.0](LICENSE).

## ⚠️ Nota Educativa

Este simulador está diseñado con **fines educativos**. El objetivo es comprender conceptos criptográficos fundamentales. Nunca debe usarse para actividades maliciosas.

---

**Última actualización**: Febrero 2026
