import streamlit as st

# Título y Subtítulo
st.title("🔐 Simulador de Ataques Criptográficos")
st.markdown("### Explorando vulnerabilidades desde César hasta AES")
st.markdown(
    '**Proyecto Final "Microcredencial Criptografía y Seguridad Digital" - ULL**'
)
st.markdown("---")

# División en dos columnas: Contexto y Objetivo (Similar a tu ejemplo de Quantum)
col1, col2 = st.columns([1, 1], gap="medium")

with col1:
    st.header("El Desafío")
    st.markdown(
        """
    La criptografía es la base de la seguridad digital. Sin embargo, **un algoritmo seguro no garantiza un sistema seguro**. 
    
    A lo largo de la historia, y aún hoy en día con estándares modernos como AES, la seguridad falla no porque las matemáticas estén rotas, sino por:
    * **Debilidades estadísticas** en algoritmos antiguos.
    * **Errores de implementación** (como reusar un *nonce*).
    * **Fugas de información** lateral (como un *Padding Oracle*).

    La pregunta es: **¿Podemos romper un cifrado sin conocer la clave, solo analizando los patrones del texto o los errores del servidor?**
    """
    )

    st.info(
        "Este simulador no utiliza herramientas automáticas de hacking. Implementamos la lógica matemática y estadística desde cero (Python) para entender cómo y por qué ocurren estas rupturas."
    )

with col2:
    st.header("La Solución: Criptoanálisis")
    st.markdown(
        """
    El objetivo de este proyecto es desmitificar los ataques criptográficos mediante la simulación práctica.
    
    **Objetivos del Proyecto:**
    1. **Entender** las debilidades de los cifrados clásicos (César y Vigenère) mediante análisis de frecuencia e Índice de Coincidencia.
    2. **Explotar** vulnerabilidades en modos de operación modernos (AES-CBC y AES-GCM).
    3. **Visualizar** cómo la estadística y los errores lógicos revelan el texto plano.
    """
    )

st.markdown("---")

# Sección visual o explicativa intermedia
st.header("Cronología de Ataques")

c_img, c_txt = st.columns([1, 2])

with c_img:
    # Puedes usar una URL de una imagen libre de derechos o subir una a tu carpeta 'images'
    st.image(
        image="images/criptoanalisis-de-cesar-a-AES.png",
        caption="De la máquina Enigma a la Ciberseguridad moderna",
        width="stretch",
    )

with c_txt:
    st.markdown("### ¿Qué vamos a simular?")
    st.markdown(
        """
    * **La Era Clásica:** Donde el lenguaje nos delata. Usaremos la frecuencia de las letras (la 'E' en español) para romper **César** y métodos estadísticos (Kasiski + Friedman) para romper **Vigenère**.
    
    * **La Era Moderna (Bloques):** Atacaremos **AES en modo CBC**. Simularemos un servidor que revela si el relleno (padding) es correcto, permitiéndonos descifrar el mensaje byte a byte sin la clave (**Padding Oracle Attack**).
    
    * **La Era Moderna (Flujo):** Atacaremos **AES-GCM**. Demostraremos cómo un simple error de configuración (reusar el número aleatorio o *Nonce*) destruye la confidencialidad mediante propiedades XOR.
    """
    )

st.markdown("---")

# Resumen de los módulos (Overview)
st.header("Módulos del Simulador")

col_a, col_b, col_c = st.columns(3)

with col_a:
    st.subheader("1. Cifrados Monoalfabéticos")
    st.markdown(
        """
    * **Cifrado César:** Ataque por Fuerza Bruta y Análisis de Frecuencia.
    * **Cifrado Monoalfabético:** Espacio de claves de $26!$.
    """
    )

with col_b:
    st.subheader("2. Cifrados Polialfabéticos")
    st.markdown(
        """
    * **Vigenère:** El cifrado "indescifrable" durante siglos.
    * **Kasiski:** Búsqueda de patrones repetidos.
    * **Índice de Coincidencia:** Validación estadística.
    """
    )

with col_c:
    st.subheader("3. Ataques Modernos")
    st.markdown(
        """
    * **AES-CBC Padding Oracle:** Explotando mensajes de error.
    * **AES-GCM Nonce Reuse:** El peligro del *Copy-Paste* en criptografía.
    * **Visualización interactiva.**
    """
    )

st.markdown("---")
st.caption(
    "Desarrollado por Himar Edhey Hernández Alonso | Microcredencial Criptografía y Seguridad Digital | 2026"
)
