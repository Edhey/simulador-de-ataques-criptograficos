import streamlit as st

# Configuración de la página global
st.set_page_config(layout="wide", page_title="Simulador Criptográfico", page_icon="🔐")

# Definición de las páginas
# 1. Introducción
pg_intro = st.Page("views/intro.py", title="Introducción", icon="🏠")

# 2. Cifrados Clásicos (Monoalfabético: César)
# Crea un archivo vacío en views/clasicos.py para que esto funcione
pg_monoalphabetic = st.Page(
    "views/clasicos-monoalfabetico.py",
    title="Cifrados Clásicos Monoalfabéticos",
    icon="🏛️",
)

# 3. Cifrados Clásicos (Polialfabético)
# Crea un archivo vacío en views/clasicos-polialfabetico.py
pg_polialphabetic = st.Page(
    "views/clasicos-polialfabetico.py", title="Análisis Vigenère", icon="📊"
)

# 4. Ataques Modernos (AES)
# Crea un archivo vacío en views/modernos.py
pg_modern = st.Page("views/modernos.py", title="Ataques Modernos", icon="💣")

# Sistema de Navegación
pg = st.navigation(
    {
        "Proyecto": [pg_intro],
        "Fase 1: Clásicos": [pg_monoalphabetic, pg_polialphabetic],
        "Fase 2: Modernos": [pg_modern],
    }
)

# Ejecutar la navegación
pg.run()

# Footer del Sidebar
with st.sidebar:
    st.caption("🎓 Microcredencial Criptografía y Seguridad Digital - ULL")
    st.caption("Autor: Himar Edhey Hernández Alonso")
