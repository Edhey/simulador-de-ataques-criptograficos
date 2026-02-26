import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import unicodedata
from utils import (
    vigenere_cipher,
    kasiski_get_candidates,
    index_of_coincidence,
    autocorrelacion,
    solve_caesar_chi_squared,
)


def clean_text(text: str) -> str:
    """Elimina acentos y caracteres no alfabéticos."""
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    return "".join(filter(str.isalpha, text)).upper()


st.header("🔐 Cifrado Polialfabético (Vigenère)")
st.markdown(
    """
El cifrado Vigenère usa una palabra clave para aplicar múltiples cifrados César intercalados.
Fue considerado indescifrable ("Le Chiffre Indéchiffrable") hasta el siglo XIX.
"""
)

tab_enc, tab_hack = st.tabs(["⚙️ Cifrador", "🕵️ Criptoanálisis"])

# PESTAÑA 1: CIFRADO
with tab_enc:
    col1, col2 = st.columns(2)

    with col1:
        msg_vig = st.text_area(
            "Mensaje",
            "EN UN LUGAR DE LA MANCHA, DE CUYO NOMBRE NO QUIERO ACORDARME, NO HA MUCHO TIEMPO QUE VIVIA UN HIDALGO DE LOS DE LANZA EN ASTILLERO, ADARGA ANTIGUA, ROCIN FLACO Y GALGO CORREDOR.",
            height=150,
        )
        key_vig = st.text_input("Clave Secreta", "CLAVE").upper()

    with col2:
        st.markdown("**Operaciones**")
        if st.button("🔒 Cifrar Texto"):
            res = vigenere_cipher(msg_vig, key_vig, decrypt=False)
            st.session_state["vig_ciphertext"] = res
            st.success("¡Texto cifrado!")
            st.code(res)

        if st.button("🔓 Descifrar Texto"):
            res = vigenere_cipher(msg_vig, key_vig, decrypt=True)
            st.info("Texto claro:")
            st.code(res)

# PESTAÑA 2: HACKING (EL PROYECTO FUERTE)
with tab_hack:
    st.subheader("Ataque Estadístico: Kasiski + Friedman")
    st.markdown(
        "Si no tenemos la clave, debemos deducir primero su **longitud** y luego sus **letras**."
    )

    # Entrada de texto cifrado (Carga desde sesión o por defecto)
    default_cipher = st.session_state.get(
        "vig_ciphertext",
        "GY UI PWRAM HG WA HEPNHV, HG NUTS PZMWVG YO LYKPRJ EEZRYETXE, IS JL MPGJZ TDIOAO LYG GIQMC FN CMFLLBS FP LJW FP LVRBL EI EUEIGPGCO, VHCCGV EPEIBYC, COXMP QLVGQ J GVPIZ CJVTPDJV.",
    )
    target = st.text_area("Texto Cifrado a Analizar", default_cipher, height=150)

    if target is None or target.strip() == "":
        st.warning("⚠️ Por favor, ingresa un texto cifrado para analizar.")
        cleaned_target = ""
        target = ""
    else:
        cleaned_target = clean_text(target)

    if len(cleaned_target) < 50:
        st.warning(
            "⚠️ El texto es muy corto para un análisis estadístico fiable. Prueba con un párrafo largo."
        )

    # --- PASO 1: LONGITUD ---
    st.markdown("### Paso 1: Encontrar la Longitud de la Clave ($L$)")

    col_k1, col_k2 = st.columns(2)

    with col_k1:
        st.markdown("**Método 1: Kasiski**")
        seq_len_slider = st.slider(
            "Longitud de secuencia (2=Bigramas, 3=Trigramas...)",
            min_value=2,
            max_value=5,
            value=3,
            help="Textos cortos necesitan secuencias más pequeñas (2), pero generan más ruido. Textos largos permiten secuencias mayores (3 o 4) que son más precisas.",
        )

        if st.button("Buscar Patrones Repetidos"):
            try:
                candidates = kasiski_get_candidates(
                    cleaned_target, seq_len=seq_len_slider
                )
            except ValueError as e:
                # st.error(str(e))
                candidates = []

            if candidates:
                df_k = pd.DataFrame(candidates[:5], columns=["Longitud", "Frecuencia"])
                st.dataframe(df_k, width="stretch", hide_index=True)

                top_candidate = df_k.iloc[0]["Longitud"]
                st.info(
                    f"💡 **Interpretación:** Kasiski sugiere que la clave podría tener longitud **{top_candidate}** (o un múltiplo/divisor), ya que es el factor más repetido en las distancias."
                )
                st.warning(
                    "⚠️ **Atención:** Kasiski es propenso a *falsos positivos* debido a repeticiones accidentales en el texto. **Debes usar el Paso 2 (Índice de Coincidencia)** para confirmar la longitud correcta."
                )
            else:
                st.error(
                    f"No se encontraron patrones repetidos de longitud {seq_len_slider} (Prueba a bajar el slider a 2 o usa un texto más largo)."
                )

    with col_k2:
        st.markdown("**Método 2: Autocorrelación (Visual)**")
        max_len_slider = st.slider("Desplazamiento Máximo", 5, 30, 20)

        # Gráfico en tiempo real
        hits = autocorrelacion(cleaned_target, max_len_slider)
        if hits:
            fig, ax = plt.subplots(figsize=(6, 3))
            ax.bar(range(1, len(hits) + 1), hits, color="skyblue")
            ax.set_xlabel("Desplazamiento")
            ax.set_ylabel("Coincidencias")
            ax.set_title("Picos = Múltiplos de la Clave")
            ax.grid(axis="y", linestyle="--", alpha=0.7)
            st.pyplot(fig)

    # --- PASO 2: VERIFICACIÓN IC ---
    st.divider()
    st.markdown("### Paso 2: Verificación con Índice de Coincidencia")

    if st.button("Calcular IC para longitudes probables"):
        results = []

        # Probamos longitudes de 1 a 20
        for L in range(1, 21):
            # Promedio de IC de las columnas
            ics = []
            for i in range(L):
                col = cleaned_target[i::L]
                ics.append(index_of_coincidence(col))
            avg_ic = sum(ics) / len(ics)
            results.append(avg_ic)

        # Visualización IC vs Longitud
        fig2, ax2 = plt.subplots(figsize=(10, 4))
        colors = ["green" if x > 0.06 else "gray" for x in results]
        ax2.bar(range(1, 21), results, color=colors)
        ax2.axhline(y=0.077, color="red", linestyle="--", label="IC Español (0.077)")
        ax2.axhline(y=0.038, color="blue", linestyle="--", label="IC Aleatorio (0.038)")
        ax2.set_xlabel("Posible Longitud de Clave")
        ax2.set_ylabel("IC Promedio")
        ax2.legend()
        st.pyplot(fig2)

        # Heurística para sugerir la mejor longitud
        # Buscamos el primer pico significativo > 0.065
        probable_len = 0
        for i, val in enumerate(results):
            if val > 0.065:
                probable_len = i + 1
                break

        if probable_len > 0:
            st.success(f"✅ La longitud más probable es **{probable_len}**")
            st.session_state["detected_len"] = probable_len
        else:
            st.warning(
                "No se detectó una longitud clara. El texto podría ser aleatorio o muy corto."
            )

    # --- PASO 3: DESCIFRADO FINAL ---
    st.divider()
    st.markdown("### Paso 3: Recuperación de la Clave")

    L_final = st.number_input(
        "Longitud confirmada",
        min_value=1,
        value=st.session_state.get("detected_len", 5),
    )

    if st.button("💥 Romper Cifrado"):
        recovered_key = ""

        # Ataque columna por columna (Chi-cuadrado)
        for i in range(L_final):
            col = cleaned_target[i::L_final]
            key_char = solve_caesar_chi_squared(col)
            recovered_key += key_char

        st.header(f"Clave Recuperada: `{recovered_key}`")

        # Descifrar muestra
        decrypted = vigenere_cipher(target, recovered_key, decrypt=True)
        st.text_area("Mensaje Recuperado", decrypted, height=150)
