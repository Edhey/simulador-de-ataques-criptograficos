import streamlit as st
import pandas as pd
from collections import Counter
from utils import ALPHABET, FREQ_ES, caesar_cipher, get_random_mono_key, mono_transform


def analyze_frequency(text: str):
    """Devuelve un DataFrame con la frecuencia de letras del texto."""
    total = len([c for c in text if c.isalpha()])
    if total == 0:
        return pd.DataFrame()

    counts = Counter(c for c in text.upper() if c.isalpha())
    freqs = {k: (v / total) * 100 for k, v in counts.items()}

    # Rellenar letras que faltan con 0 para el gráfico
    for char in ALPHABET:
        if char not in freqs:
            freqs[char] = 0

    df = pd.DataFrame(list(freqs.items()), columns=["Letra", "Frecuencia"])
    return df.sort_values("Letra")


# --- INTERFAZ DE USUARIO (Frontend) ---

st.header("🏛️ Cifrados Clásicos")
st.markdown(
    "Explora cómo funcionaban los primeros métodos de cifrado y por qué son inseguros hoy en día."
)

tab1, tab2 = st.tabs(["Cifrado César", "Sustitución Monoalfabética"])

# ==========================================
# PESTAÑA 1: CÉSAR
# ==========================================
with tab1:
    st.subheader("El Cifrado César")
    st.caption("Cada letra se desplaza un número fijo de posiciones.")

    col_input, col_viz = st.columns([1, 1])

    with col_input:
        msg_caesar = st.text_area(
            "Mensaje de entrada", "ESTE ES UN MENSAJE SECRETO", height=100
        )
        shift = st.slider("Desplazamiento (Clave $k$)", 1, 25, 4)

        c1, c2 = st.columns(2)
        if c1.button("🔒 Cifrar", key="btn_enc_caesar"):
            res = caesar_cipher(msg_caesar, shift, decrypt=False)
            st.session_state["caesar_result"] = res
            st.success(f"Resultado: {res}")

        if c2.button("🔓 Descifrar", key="btn_dec_caesar"):
            res = caesar_cipher(msg_caesar, shift, decrypt=True)
            st.session_state["caesar_result"] = res
            st.info(f"Resultado: {res}")

    with col_viz:
        st.markdown("#### Visualización del Desplazamiento")
        # Mostramos el mapeo de letras visualmente
        original = list(ALPHABET)
        shifted = [chr((ord(c) - 65 + shift) % 26 + 65) for c in original]

        df_map = pd.DataFrame([original, shifted], index=["Original", "Cifrado"])
        st.dataframe(df_map, width="stretch")

        # Diagrama contextual opcional
        st.caption("Diagrama de cambio de posición ")

    st.divider()

    # --- SECCIÓN DE ATAQUES CÉSAR ---
    st.subheader("🕵️ Zona de Criptoanálisis (Hacking)")

    attack_type = st.radio(
        "Selecciona técnica de ataque:",
        ["Fuerza Bruta", "Análisis de Frecuencia"],
        horizontal=True,
    )

    target_text = st.text_input(
        "Texto a romper (Cifrado)",
        value=st.session_state.get("caesar_result", "IWXI IW YR QIRWENI WIGVIXS"),
    )
    if target_text is None or target_text.strip() == "":
        st.warning(
            "⚠️ El texto no puede estar vacío. Se usará el texto cifrado de ejemplo."
        )
        target_text = "IWXI IW YR QIRWENI WIGVIXS"

    if attack_type == "Fuerza Bruta":
        st.markdown(
            "Como el espacio de claves es pequeño ($26$), podemos probarlas todas."
        )
        if st.button("Lanzar Fuerza Bruta"):
            results = {}
            for k in range(26):
                dec = caesar_cipher(target_text, k, decrypt=True)
                results[f"Desplazamiento-{k}"] = dec

            # Mostramos resultados en una tabla interactiva
            df_brute = pd.DataFrame(
                list(results.items()), columns=["Clave Probada", "Texto Resultante"]
            )
            st.dataframe(
                df_brute,
                width="stretch",
                height=600,
                hide_index=True,
                column_config={
                    "Clave Probada": st.column_config.Column(width="small"),
                    "Texto Resultante": st.column_config.Column(width="large"),
                },
            )

    elif attack_type == "Análisis de Frecuencia":
        st.markdown(
            "Comparamos la frecuencia de las letras del texto cifrado con el idioma Español."
        )

        col_stats_1, col_stats_2 = st.columns(2)

        with col_stats_1:
            st.markdown("**Frecuencia en Texto Cifrado**")
            df_cipher = analyze_frequency(target_text)
            if not df_cipher.empty:
                st.bar_chart(df_cipher.set_index("Letra"))

                # Heurística simple: Letra más común es E
                most_common = df_cipher.sort_values("Frecuencia", ascending=False).iloc[
                    0
                ]["Letra"]
                probable_shift = (ord(most_common) - ord("E")) % 26
                st.metric("Letra más común detectada", most_common)
                st.success(
                    f"Desplazamiento sugerido: {probable_shift} (Asumiendo {most_common} = E)"
                )

        with col_stats_2:
            st.markdown("**Referencia Español**")
            df_ref = pd.DataFrame(
                list(FREQ_ES.items()), columns=["Letra", "Frecuencia"]
            )
            st.bar_chart(df_ref.set_index("Letra"), color="#ffaa00")

# ==========================================
# PESTAÑA 2: MONOALFABÉTICO
# ==========================================
with tab2:
    st.subheader("Sustitución Monoalfabética")
    st.caption(
        "Cada letra se reemplaza por otra distinta según una clave aleatoria (Permutación)."
    )

    # Gestión de Claves
    if "mono_key" not in st.session_state:
        st.session_state["mono_key"] = get_random_mono_key()

    col_mono_1, col_mono_2 = st.columns([2, 1])

    with col_mono_1:
        msg_mono = st.text_area("Mensaje", "ESTE ES UN MENSAJE SECRETO", height=100)

        if st.button("Generar Nueva Clave Aleatoria"):
            st.session_state["mono_key"] = get_random_mono_key()

        current_key = st.text_input(
            "Clave Actual (Alfabeto desordenado)", st.session_state["mono_key"]
        )
        if current_key is None or current_key.strip() == "":
            st.warning("⚠️ La clave no puede estar vacía. Se usará la clave aleatoria.")
            current_key = st.session_state["mono_key"]

        c_m1, c_m2 = st.columns(2)
        if c_m1.button("🔒 Cifrar", key="btn_enc_mono"):
            res = mono_transform(msg_mono, current_key, decrypt=False)
            st.session_state["mono_result"] = res
            st.code(res)

        if c_m2.button("🔓 Descifrar", key="btn_dec_mono"):
            res = mono_transform(msg_mono, current_key, decrypt=True)
            st.code(res)

    with col_mono_2:
        st.info(f"Espacio de claves: $26! \\approx 4 \\times 10^{{26}}$")
        st.warning("¡La fuerza bruta es imposible aquí!")
        st.markdown("**Mapeo:**")
        st.text(f"A B C D ...\n↓ ↓ ↓ ↓\n{current_key[:4]} ...")

    st.divider()

    st.subheader("🕵️ Análisis de Frecuencia")
    st.markdown("Aunque la fuerza bruta falla, la estadística sigue funcionando.")

    target_mono = st.text_area(
        "Texto a analizar", value=st.session_state.get("mono_result", "")
    )

    if target_mono:
        df_mono_freq = analyze_frequency(target_mono)
        st.bar_chart(df_mono_freq.set_index("Letra"))
        st.caption(
            "Si ves una barra muy alta (ej: 'X'), probablemente 'X' sea la 'E' o la 'A' del mensaje original."
        )
