import streamlit as st
import pandas as pd
from utils import caesar_state_prep, caesar_oracle, vigenere_state_prep, vigenere_oracle, GroverUI


# ==========================================
# 3. INTERFAZ DE USUARIO (Streamlit)
# ==========================================
st.set_page_config(layout="wide")
st.header("⚛️ Criptoanálisis Cuántico (Algoritmo de Grover)")
st.markdown("Simulación del colapso de seguridad en cifrados clásicos utilizando superposición y evaluación cuántica paralela.")

tab_caesar, tab_vig = st.tabs(["Cifrado César", "Cifrado Vigenère"])

# --- PESTAÑA 1: CÉSAR ---
with tab_caesar:
    st.subheader("Ataque de Texto Plano Conocido (César)")
    st.markdown("Utilizamos dos pares conocidos de texto plano/cifrado y un Sumador Cuántico de Draper en el oráculo para evaluar la suma modular en superposición.")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("**Parámetros de Entrada**")
        p0 = st.number_input("P0 (Texto Plano 1)", value=2, min_value=0, max_value=15)
        c0 = st.number_input("C0 (Texto Cifrado 1)", value=7, min_value=0, max_value=15)
        p1 = st.number_input("P1 (Texto Plano 2)", value=14, min_value=0, max_value=15)
        c1 = st.number_input("C1 (Texto Cifrado 2)", value=3, min_value=0, max_value=15)
        
        if st.button("🚀 Ejecutar Grover (César)", type="primary"):
            with st.spinner("Compilando circuito y ejecutando en simulador cuántico (1024 shots)..."):
                prep = caesar_state_prep(p0, p1)
                oracle = caesar_oracle(c0, c1)
                solver = GroverUI(oracle=oracle, num_solutions=1, state_preparation=prep, search_space_size=16, diffusion_registers=[[0, 1, 2, 3]])
                
                results = solver.search(shots=1024)
                st.session_state['caesar_res'] = results
                st.session_state['caesar_iter'] = solver.optimal_iterations

    with col2:
        if 'caesar_res' in st.session_state:
            res = st.session_state['caesar_res']
            most_frequent = max(res, key=res.get)
            k_bits = most_frequent[10:14]
            measured_k = int(k_bits, 2)
            prob = (res[most_frequent] / 1024) * 100
            
            st.success(f"**Clave Recuperada (K):** {measured_k} | **Precisión:** {prob:.1f}%")
            
            c_m1, c_m2 = st.columns(2)
            c_m1.metric("Iteraciones Cuánticas", st.session_state['caesar_iter'], delta="-90% vs Clásico", delta_color="inverse")
            c_m2.metric("Probabilidad de Éxito", f"{prob:.1f}%")
            
            # Gráfico
            df_plot = pd.DataFrame(list(res.items()), columns=['Estado', 'Conteos']).sort_values('Conteos', ascending=False).head(10)
            st.bar_chart(df_plot.set_index('Estado'), color="#0066FF")

# --- PESTAÑA 2: VIGENÈRE ---
with tab_vig:
    st.subheader("Amplificación de Amplitud Paralela (Vigenère)")
    st.markdown("Para evitar el entrelazamiento masivo y una explosión de iteraciones, aplicamos difusores independientes a cada fragmento de la clave polialfabética. El código es dinámico y escala automáticamente según el número de bloques introducidos.")
    
    col_v1, col_v2 = st.columns([1, 2])
    with col_v1:
        st.markdown("**Bloques Conocidos (P y C)**")
        st.caption("Introduce números del 0 al 15 separados por comas.")
        
        p_input = st.text_input("P (Texto Plano)", "4, 1, 9")
        c_input = st.text_input("C (Texto Cifrado)", "6, 11, 8")
        
        if st.button("🚀 Ejecutar Grover (Vigenère)", type="primary"):
            try:
                # Convertimos el texto a listas de enteros
                P_vals = [int(x.strip()) for x in p_input.split(',')]
                C_vals = [int(x.strip()) for x in c_input.split(',')]
                
                if len(P_vals) != len(C_vals):
                    st.error("Las listas de P y C deben tener la misma longitud.")
                elif len(P_vals) > 3:
                    st.warning("⚠️ Cuidado: Simular más de 3 bloques (>27 cúbits) podría colapsar la memoria RAM de tu ordenador local.")
                else:
                    with st.spinner(f"Construyendo circuito dinámico para {len(P_vals)} bloques y evaluando en paralelo..."):
                        num_bits = 4
                        n_blocks = len(P_vals)
                        
                        prep_v = vigenere_state_prep(P_vals, num_bits)
                        oracle_v = vigenere_oracle(C_vals, num_bits)
                        
                        # Generamos los difusores independientes dinámicamente según n_blocks
                        diff_regs = [list(range(i * num_bits, (i + 1) * num_bits)) for i in range(n_blocks)]
                        
                        solver_v = GroverUI(oracle=oracle_v, num_solutions=1, state_preparation=prep_v, search_space_size=16, diffusion_registers=diff_regs)
                        
                        results_v = solver_v.search(shots=1024)
                        st.session_state['vig_res'] = results_v
                        st.session_state['vig_iter'] = solver_v.optimal_iterations
                        st.session_state['vig_blocks'] = n_blocks
            except ValueError:
                st.error("Por favor, introduce solo números enteros separados por comas.")

    with col_v2:
        if 'vig_res' in st.session_state:
            res_v = st.session_state['vig_res']
            n_blocks = st.session_state['vig_blocks']
            num_bits = 4
            
            most_frequent_v = max(res_v, key=res_v.get)
            
            # Extraemos las subclaves dinámicamente desde el string binario (que se lee de derecha a izquierda)
            measured_k = []
            for i in range(n_blocks):
                # Calcular los índices de inicio y fin para cada bloque K_i
                start_idx = len(most_frequent_v) - ((i + 1) * num_bits)
                end_idx = len(most_frequent_v) - (i * num_bits)
                k_bits = most_frequent_v[start_idx:end_idx]
                measured_k.append(int(k_bits, 2))
                
            prob_v = (res_v[most_frequent_v] / 1024) * 100
            
            # Mostramos las subclaves
            claves_str = ", ".join([f"K{i}={k}" for i, k in enumerate(measured_k)])
            st.success(f"**Sub-claves Recuperadas:** {claves_str}")
            
            cv1, cv2, cv3 = st.columns(3)
            # Calculamos las iteraciones evitadas si hubiera sido un difusor global (2^(n_blocks * 4))
            espacio_global = 2**(n_blocks * num_bits)
            # Iteraciones globales ~= (pi/4) * sqrt(espacio_global)
            import math
            iteraciones_globales = math.floor(math.pi / 4 * math.sqrt(espacio_global))
            iteraciones_ahorradas = iteraciones_globales - st.session_state['vig_iter']
            
            cv1.metric("Iteraciones", st.session_state['vig_iter'], delta=f"Evitadas {iteraciones_ahorradas} iter.", delta_color="inverse")
            cv2.metric("Espacio Teórico Entrelazado", f"{espacio_global} ({n_blocks * num_bits} bits)")
            cv3.metric("Éxito de Convergencia", f"{prob_v:.1f}%")
            
            df_plot_v = pd.DataFrame(list(res_v.items()), columns=['Estado', 'Conteos']).sort_values('Conteos', ascending=False).head(5)
            st.bar_chart(df_plot_v.set_index('Estado'), color="#B22222")
            st.caption(f"Estado ganador dominante: {most_frequent_v}")