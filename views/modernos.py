import streamlit as st
import time
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from utils import PaddingOracle, xor_bytes


def encrypt_mock(msg: str, key: bytes):
    """Simula al usuario legítimo cifrando un mensaje para enviarlo."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))
    return iv, ciphertext


def attack_block_logic(oracle: PaddingOracle, c_target: bytes, c_prev: bytes):
    """Generador visual del ataque (un solo bloque).
    Se mantiene aquí porque usa 'yield' para actualizar la UI en tiempo real."""
    block_size = 16
    intermediate = [0] * block_size
    decrypted_bytes = [0] * block_size

    for i in range(block_size - 1, -1, -1):
        padding_value = block_size - i

        # Construir IV forjado
        prefix = [0] * i
        suffix = [intermediate[j] ^ padding_value for j in range(i + 1, block_size)]

        found = False
        for val in range(256):
            test_iv = bytes(prefix + [val] + suffix)

            if oracle.check_padding(c_target, iv=test_iv):
                intermediate[i] = val ^ padding_value
                decrypted_byte = intermediate[i] ^ c_prev[i]
                decrypted_bytes[i] = decrypted_byte
                found = True

                # Yield para actualizar la UI: (progreso, byte_encontrado, posición)
                yield (block_size - i) / block_size, decrypted_byte, i
                break

        if not found:
            yield (block_size - i) / block_size, None, i

    return bytes(decrypted_bytes)


def gcm_encrypt_unsafe(msg: str, key: bytes, nonce: bytes):
    """Cifrado GCM para la demostración del Nonce Reuse."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, _ = cipher.encrypt_and_digest(msg.encode())
    return ciphertext


st.header("💣 Ataques a Cifrados Modernos (AES)")
st.markdown(
    """
Aquí explotamos **errores de implementación** y **fugas de información lateral**. 
El algoritmo AES es seguro matemáticamente, pero el *modo de uso* puede ser fatal.
"""
)

tab_cbc, tab_gcm = st.tabs(["Oracle Attack (CBC)", "Nonce Reuse (GCM)"])

# Padding Oracle Attack (CBC)
with tab_cbc:
    st.subheader("💥 Padding Oracle Attack (AES-CBC)")
    st.markdown(
        """
    **El Escenario:** Un servidor recibe un mensaje cifrado. Si el descifrado falla por *Padding Incorrecto*, devuelve un error específico.
    **El Ataque:** Usamos ese error como un "Oráculo" (Verdadero/Falso) para descifrar el mensaje byte a byte sin la clave.
    """
    )

    col_setup, col_attack = st.columns([1, 2])

    # Inicializamos la clave del servidor en la sesión para que no cambie al recargar
    if "oracle_key" not in st.session_state:
        st.session_state["oracle_key"] = get_random_bytes(16)
    oracle = PaddingOracle(st.session_state["oracle_key"])

    with col_setup:
        st.markdown("### 1. Configuración")
        secret_msg = st.text_input("Mensaje Secreto", "HOLA MUNDO", max_chars=15)

        if st.button("🔒 Enviar al Servidor"):
            iv, ct = encrypt_mock(secret_msg, st.session_state["oracle_key"])
            st.session_state["cbc_iv"] = iv
            st.session_state["cbc_ct"] = ct
            st.success("Mensaje interceptado.")

        if "cbc_ct" in st.session_state:
            st.markdown("**Datos Interceptados:**")
            st.code(f"IV: {st.session_state['cbc_iv'].hex()}", language="text")
            st.code(f"CT: {st.session_state['cbc_ct'].hex()}", language="text")

    with col_attack:
        st.markdown("### 2. Ejecutar Exploit")
        st.caption("El ataque modificará el IV para engañar al servidor.")

        if "cbc_ct" in st.session_state:
            if st.button("💀 Lanzar Ataque"):
                # Preparamos los bloques (Atacamos el primer bloque usando el IV)
                target_block = st.session_state["cbc_ct"][:16]
                prev_block = st.session_state["cbc_iv"]

                # Elementos de la UI
                progress_bar = st.progress(0)
                status_text = st.empty()
                terminal = st.code("Iniciando conexión...", language="bash")
                recovered_chars = ["?"] * 16

                # Ejecutar generador
                for progress, byte_val, pos in attack_block_logic(
                    oracle, target_block, prev_block
                ):
                    progress_bar.progress(progress)

                    if byte_val is not None:
                        char_repr = chr(byte_val) if 32 <= byte_val <= 126 else "."
                        recovered_chars[pos] = char_repr
                        current_str = "".join(recovered_chars)

                        status_text.markdown(
                            f"**Rompiendo Byte {pos}...** ¡Encontrado: `{char_repr}`!"
                        )
                        terminal.code(
                            f"""
                        [+] Oracle Hit! Padding OK.
                        [+] Decrypting offset {pos}: {hex(byte_val)} ({char_repr})
                        [>] Result: {current_str}
                        """
                        )
                        time.sleep(0.1)

                st.balloons()
                st.success(f"Mensaje Recuperado: {''.join(recovered_chars)}")
                st.caption(
                    "Nota: Los últimos bytes son el padding PKCS7 (ej: \\x06\\x06...)"
                )

# Nonce Reuse Attack (GCM)
with tab_gcm:
    st.subheader("⚡ Reutilización de Nonce (AES-GCM/CTR)")

    st.markdown(
        r"""
    En cifrados de flujo (Stream Ciphers), $C = P \oplus K_{stream}$. 
    
    Si usamos la misma clave y el mismo **Nonce** para dos mensajes:
    1. $C_1 = P_1 \oplus K_{stream}$
    2. $C_2 = P_2 \oplus K_{stream}$
    3. $C_1 \oplus C_2 = (P_1 \oplus P_2)$
    
    ¡El cifrado se cancela y los textos planos quedan "pegados"!
    """
    )

    # Setup inicial
    st.divider()
    col_gcm_1, col_gcm_2 = st.columns(2)

    if "gcm_key" not in st.session_state:
        st.session_state["gcm_key"] = get_random_bytes(32)
        st.session_state["gcm_nonce"] = get_random_bytes(12)  # NONCE FIJO (EL ERROR)

    with col_gcm_1:
        msg_a = st.text_input("Mensaje A (Víctima 1)", "Transferir 1000€ a Alice")
        msg_b = st.text_input("Mensaje B (Víctima 2)", "Transferir 9000€ a Bob!!")

        if st.button("📧 Interceptar Mensajes"):
            # Ciframos con EL MISMO NONCE
            c1 = gcm_encrypt_unsafe(
                msg_a, st.session_state["gcm_key"], st.session_state["gcm_nonce"]
            )
            c2 = gcm_encrypt_unsafe(
                msg_b, st.session_state["gcm_key"], st.session_state["gcm_nonce"]
            )

            st.session_state["xor_stream"] = xor_bytes(c1, c2)
            st.warning("⚠️ ¡Alerta! Se ha detectado reutilización de Nonce.")

    with col_gcm_2:
        if "xor_stream" in st.session_state:
            st.markdown("**Análisis Diferencial (XOR)**")
            st.code(st.session_state["xor_stream"].hex(), language="text")
            st.caption("Esta cadena hexadecimal contiene la 'suma' de ambos mensajes.")

    # Crib Dragging
    st.divider()
    st.subheader("🛠️ Herramienta: Crib Dragging")
    st.markdown(
        "Arrastra una palabra probable (Crib) para ver si aparece texto legible."
    )

    if "xor_stream" in st.session_state:
        crib = st.text_input("Palabra probable (ej: 'Transferir')", "Transferir")

        if crib:
            st.markdown("### Resultados del Arrastre")

            xor_data = st.session_state["xor_stream"]
            crib_bytes = crib.encode()
            results = []

            # Algoritmo de arrastre
            for i in range(len(xor_data) - len(crib_bytes) + 1):
                chunk = xor_data[i : i + len(crib_bytes)]
                try:
                    revealed = xor_bytes(chunk, crib_bytes).decode(
                        "utf-8", errors="ignore"
                    )
                    clean_revealed = "".join(
                        [c if c.isprintable() else "." for c in revealed]
                    )
                except:
                    clean_revealed = "Error"

                results.append({"Posición": i, "Texto Revelado": clean_revealed})

            df_results = pd.DataFrame(results)
            st.dataframe(
                df_results.style.apply(
                    lambda x: [
                        (
                            "background-color: #d4edda; color: #155724"
                            if crib in x["Texto Revelado"]
                            or "Alice" in x["Texto Revelado"]
                            or "Bob" in x["Texto Revelado"]
                            else ""
                        )
                        for _ in x
                    ],
                    axis=1,
                ),
                width="stretch",
                hide_index=True,
            )

            st.caption(
                "Busca filas iluminadas donde el 'Texto Revelado' tenga sentido semántico."
            )
