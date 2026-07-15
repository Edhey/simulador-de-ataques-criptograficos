#!/usr/bin/env python
# coding: utf-8

# ### Simulador de ataques clásicos y modernos
#
# Este es el notebook hecho script para poder importar las funciones contiene el proyecto final de la microcredencial "Criptografía y Seguridad Digital" de la Universidad de La Laguna. El objetivo es simular diversos ataques criptográficos, tanto clásicos como modernos, utilizando Python. Por ello, se han implementado los siguientes ataques:
# - Análisis de frecuencia
# - IC + Kasiski
# - Padding oracle (simulado)
# - Ataque por nonce reutilizado
# - Visualizaciones usando matplotlib o Streamlit
#
# ---
from collections import Counter
import string
import random
import unicodedata
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from collections import defaultdict
import math


# # 1. Cifrados Clásicos


# Antes de comenzar definiremos el mensaje que vamos a cifrar en el resto de secciones:

# ## Cifrado César

# En esta sección, nos centraremos en el cifrado César, un método de cifrado por sustitución en el que cada letra del texto original se reemplaza por otra letra que se encuentra un número fijo de posiciones más adelante en el alfabeto. Implementaremos tanto el cifrado como el descifrado, y luego simularemos un ataque de análisis de frecuencia para intentar recuperar el mensaje original sin conocer la clave.

# ### Cifrado

# Para el cifrado, definiremos una función que tome un texto y un desplazamiento (clave) como argumentos y devuelva el texto cifrado. El desplazamiento indicará cuántas posiciones se moverán las letras en el alfabeto.


def cesar_encrypt(text: str, key: int) -> str:
    """Cifra un texto utilizando el cifrado César.

    Args:
        text (str): El texto que se desea cifrar.
        key (int): El número de posiciones que se desean desplazar las letras en el cifrado.

    Returns:
        str: El texto cifrado, con las letras desplazadas según el valor de la clave.
    """
    START = ord("A")
    ALPHABET_SIZE = 26
    result: str = ""
    for char in text.upper():
        if char.isalpha():
            result += chr((ord(char) - START + key) % ALPHABET_SIZE + START)
        else:
            result += char
    return result


# ### Descifrado

# En cuanto al descifrado, crearemos una función que reciba un texto cifrado y un desplazamiento, y devuelva el texto original. Esta función simplemente realizará el proceso inverso al cifrado, moviendo las letras hacia atrás en el alfabeto.


def cesar_decrypt(cipher: str, key: int) -> str:
    """Descifra un texto cifrado utilizando el cifrado César.

    Args:
        cipher (str): El texto cifrado que se desea descifrar.
        key (int): El número de posiciones que se han desplazado las letras en el cifrado.

    Returns:
        str: El texto descifrado, con las letras desplazadas de vuelta a su posición original.
    """
    START = ord("A")
    ALPHABET_SIZE = 26
    result: str = ""
    for char in cipher.upper():
        if char.isalpha():
            result += chr((ord(char) - START - key) % ALPHABET_SIZE + START)
        else:
            result += char
    return result


# Podríamos sintetizar esto en un único método que reciba un mensaje, una clave y una operación (cifrar o descifrar)


def caesar_cipher(text: str, key: int, decrypt: bool) -> str:
    """Cifra o descifra un texto utilizando el cifrado César.

    Args:
        text (str): El texto a cifrar o descifrar.
        key (int): La clave de cifrado (número de posiciones a desplazar).
        decrypt (bool): Indica si se desea descifrar (True) o cifrar (False).

    Returns:
        str: El texto cifrado o descifrado.
    """
    START = ord("A")
    ALPHABET_SIZE = 26
    result: str = ""
    if decrypt:
        key = -key
    for char in text.upper():
        if char.isalpha():
            result += chr((ord(char) - START + key) % ALPHABET_SIZE + START)
        else:
            result += char
    return result


def cesar_get_shift(cipher: str) -> int:
    """Determina el desplazamiento utilizado en un cifrado César analizando la
    frecuencia de las letras en el texto cifrado. Asume que la letra más frecuente en el
    texto cifrado corresponde a la letra 'E' en el idioma español, que es la letra más
    común.

    Args:
        cipher (str): El texto cifrado.

    Returns:
        int: El desplazamiento utilizado en el cifrado César.
    """
    Counter(cipher)
    most_common = Counter(cipher).most_common(1)[0][0]
    return (ord(most_common) - ord("E")) % 26


def solve_caesar_chi_squared(column: str) -> str:
    """
    Encuentra la letra clave de una columna usando Chi-cuadrado.

    Args:
        column (str): La columna de texto cifrado a analizar.
    Returns:
        str: La letra clave estimada para esa columna.
    """
    n = len(column)
    counts = Counter(column)
    min_chi = float("inf")
    best_shift = 0

    for shift in range(26):
        chi = 0.0
        for char_code in range(ord("A"), ord("Z") + 1):
            char = chr(char_code)
            decrypted_char = chr((ord(char) - ord("A") - shift) % 26 + ord("A"))
            observed = counts[char]
            expected = FREQ_ES.get(decrypted_char, 0) * n

            if expected > 0:
                chi += ((observed - expected) ** 2) / expected

        if chi < min_chi:
            min_chi = chi
            best_shift = shift

    return chr(best_shift + ord("A"))

# ## Cifrado Monoalfabético

# César es un caso particular de cifrado monoalfabético, donde cada letra se sustituye por otra letra fija. En esta sección, implementaremos un cifrado monoalfabético más general, donde cada letra del alfabeto puede ser reemplazada por cualquier otra letra. Esto aumenta significativamente el espacio de claves, haciendo que un ataque por fuerza bruta sea impracticable.

# Comenzamos importando la biblioteca `string` para obtener el alfabeto y luego definimos la función de cifrado monoalfabético. Esta función tomará un mensaje y una clave (que es una permutación del alfabeto) y devolverá el mensaje cifrado. Para poder elegir una permutación aleatoria del alfabeto, utilizaremos la función `random.shuffle` de la biblioteca `random`.


ALPHABET = string.ascii_uppercase
FREQ_ES = {
    "A": 12.53,
    "B": 1.42,
    "C": 4.68,
    "D": 5.86,
    "E": 13.68,
    "F": 0.69,
    "G": 1.01,
    "H": 0.70,
    "I": 6.25,
    "J": 0.44,
    "K": 0.02,
    "L": 4.97,
    "M": 3.15,
    "N": 6.71,
    "O": 8.68,
    "P": 2.51,
    "Q": 0.88,
    "R": 6.87,
    "S": 7.98,
    "T": 4.63,
    "U": 3.93,
    "V": 0.90,
    "W": 0.01,
    "X": 0.22,
    "Y": 0.90,
    "Z": 0.52,
}


def get_random_mono_key() -> str:
    """Genera una clave aleatoria válida para cifrado monoalfabético (una
    permutación del alfabeto)."""
    chars = list(ALPHABET)
    random.shuffle(chars)
    return "".join(chars)


# ### Cifrado

# En este caso ciframos un mensaje utilizando una clave que es una permutación aleatoria del alfabeto. Esto nos permite pasar de las 26 posibles claves del cifrado César a 26! posibles claves, haciendo que un ataque por fuerza bruta sea completamente inviable.


def mono_transform(text: str, key: str, decrypt: bool = False) -> str:
    """Cifrado/Descifrado Monoalfabético."""
    if decrypt:
        mapping = dict(zip(key, ALPHABET))
    else:
        mapping = dict(zip(ALPHABET, key))

    return "".join(mapping.get(c, c) for c in text.upper())


# ## Cifrado Vigenère

# A continuación, implementaremos el cifrado Vigenère, un método de cifrado por sustitución polialfabética que utiliza una palabra clave para determinar el desplazamiento de cada letra en el mensaje. Este cifrado es más seguro que el César y el monoalfabético, ya que introduce variabilidad en la sustitución de letras.

# ### Cifrado y Descifrado

# Para implementar el cifrado Vigenère, definimos una única función que toma un mensaje, una clave y un parámetro booleano `decrypt` como argumentos. La clave se repetirá a lo largo del mensaje para determinar el desplazamiento de cada letra. El cifrado se realiza sumando el valor de la letra del mensaje con el valor de la letra correspondiente de la clave, utilizando el alfabeto como referencia. Mientras que en el descifrado, se resta el valor de la letra de la clave para recuperar el mensaje original. El parametro `decrypt` nos servirá para indicar si queremos cifrar o descifrar el mensaje, evitando así tener que escribir dos funciones separadas.


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    """Cifra o descifra un texto utilizando el cifrado Vigenère.

    Args:
        text (str): El texto a cifrar o descifrar.
        key (str): La clave de cifrado (palabra clave que se repetirá a lo largo del mensaje).
        decrypt (bool, optional): Si es True, se descifra el texto. Defaults to False.

    Returns:
        str: El texto cifrado o descifrado.
    """
    ASCII_A = ord("A")
    ALPHABET_SIZE = 26
    text = text.upper()
    key = key.upper()

    result = []
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ASCII_A
            if decrypt:
                shift = -shift

            processed_char = chr(
                (ord(char) - ASCII_A + shift) % ALPHABET_SIZE + ASCII_A
            )
            result.append(processed_char)

            key_index += 1
        else:
            result.append(char)

    return "".join(result)


# Podemos añadir unos wrappers para cifrar y descifrar, que simplemente llamen a esta función con el parámetro `decrypt` adecuado.


def vigenere_encrypt(message: str, key: str) -> str:
    """Wrapper para cifrar un mensaje utilizando el cifrado Vigenère."""
    return vigenere_cipher(message, key, decrypt=False)


def vigenere_decrypt(cipher: str, key: str) -> str:
    """Wrapper para descifrar un mensaje cifrado utilizando el cifrado Vigenère."""
    return vigenere_cipher(cipher, key, decrypt=True)


# ### Ataque a Vigenère

# En este caso, un ataque por fuerza bruta no es factible debido al gran espacio de claves (dependiendo de la longitud de la clave). Además, la naturaleza polialfabética del cifrado Vigenère hace que el análisis de frecuencias tradicional no sea efectivo.
#
# Sin embargo, si conocieramos la longitud de la clave, podríamos dividir el mensaje cifrado en grupos de letras que corresponden a cada letra de la clave y realizar un análisis de frecuencias en cada grupo para intentar deducir la letra de la clave correspondiente. Para esto existen varias técnicas que veremos a continuación. Estos son métodos estadísticos que nos permiten estimar la longitud de la clave, por lo que usaremos un mensaje cifrado más largo para que los resultados sean más precisos.


def clean_text(route: str) -> str:
    """
    Reads a text file, removes spaces, accents and non-alphabetic characters, and converts it to uppercase.

    Args:
        route (str): The path to the text file to be cleaned.
    Returns:
        str: The cleaned text.
    """
    with open(route, "r", encoding="utf-8") as file:
        text = file.read()

    # Remove accents
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    # Keep only alphabetic characters and convert to uppercase
    cleaned_text = "".join(filter(str.isalpha, text)).upper()

    return cleaned_text


# #### Autocorrelación

# El método de Autocorrelación es una técnica utilizada para determinar la longitud de la clave en un cifrado Vigenère. Consiste en comparar el texto cifrado consigo mismo desplazado por diferentes cantidades. Si el desplazamiento coincide con la longitud de la clave, se observará un aumento en la coincidencia de letras, lo que sugiere que el desplazamiento es un múltiplo de la longitud de la clave.


def autocorrelacion(ciphertext: str, max_shift: int = 20) -> list[int]:
    """
    Calcula la autocorrelación de un texto cifrado para detectar la longitud de la clave.

    Args:
        ciphertext (str): El texto cifrado (solo letras A-Z).
        max_shift (int): Hasta qué desplazamiento queremos probar.

    Returns:
        list[int]: Lista con la cantidad de coincidencias para cada desplazamiento s.
                   El índice 0 corresponde a s=0 (coincidencia total),
                   el índice 1 a s=1, etc.
    """
    n = len(ciphertext)
    coincidencias = []

    for s in range(1, max_shift + 1):
        count = 0
        for i in range(n - s):
            if ciphertext[i] == ciphertext[i + s]:
                count += 1
        coincidencias.append(count)
    return coincidencias


# Este es un método más visual, ya que se pueden graficar las coincidencias para cada desplazamiento y observar claramente los picos que indican posibles longitudes de clave. Por lo que, usando matplotlib, podríamos graficar el número de coincidencias para cada desplazamiento y ver así dichos picos de manera clara.

# #### Kaisiski

# Por otra parte, el método de Kasiski es una técnica utilizada para determinar la longitud de la clave en un cifrado Vigenère. Consiste en buscar repeticiones de secuencias de letras en el texto cifrado y medir la distancia entre estas repeticiones. La idea es que si una secuencia se repite, es probable que haya sido cifrada con la misma parte de la clave, lo que sugiere que la longitud de la clave es un divisor común de las distancias entre las repeticiones.


def repeated_sequences(text: str, n: int = 3) -> dict[str, list[int]]:
    """Busca secuencias repetidas de longitud n en el texto y devuelve un diccionario
    con las secuencias y sus posiciones.

    Args:
        text (str): El texto en el que buscar las secuencias repetidas.
        n (int, optional): La longitud de las secuencias a buscar. Defaults to 3.

    Returns:
        dict[str, list[int]]: Un diccionario con las secuencias repetidas como claves y
        sus posiciones como valores.
    """
    seqs: dict[str, list[int]] = defaultdict(list)
    for i in range(len(text) - n):
        seq = text[i : i + n]
        seqs[seq].append(i)
    return {k: v for k, v in seqs.items() if len(v) > 1}


# Con este método, podemos identificar secuencias de letras que se repiten en el texto cifrado y calcular las distancias entre ellas.


# Ahora necesitamos analizar estas distancias para encontrar los divisores comunes, lo que nos dará una estimación de la longitud de la clave.


def kasiski_get_candidates(text: str, seq_len: int = 3) -> list[tuple[int, int]]:
    """Devuelve una lista de posibles longitudes de clave ordenadas por probabilidad.
    Ej: [(4, 15), (2, 10)] -> Longitud 4 apareció 15 veces como factor.


    Args:
        text (str): El texto cifrado del que se quieren obtener las posibles longitudes de clave.
        seq_len (int, optional): La longitud de las secuencias repetidas a buscar. Defaults to 3.

    Returns:
        list[tuple[int, int]]: Una lista de tuplas (longitud, frecuencia) ordenadas por
        frecuencia descendente.
    """
    seqs = repeated_sequences(text, seq_len)

    distances = []
    for positions in seqs.values():
        for i in range(len(positions) - 1):
            distances.append(positions[i + 1] - positions[i])

    if not distances:
        raise ValueError("No se encontraron secuencias repetidas en el texto.")

    factor_counts = defaultdict(int)
    for d in distances:
        for k in range(2, d + 1):
            if d % k == 0:
                factor_counts[k] += 1

    return sorted(factor_counts.items(), key=lambda x: x[1], reverse=True)


# ##### Índice de Coincidencia (IC)

# Una de las técnicas más comunes para determinar la longitud de la clave en un cifrado Vigenère es el Índice de Coincidencia (IC). El IC mide la probabilidad de que dos letras seleccionadas al azar del texto cifrado sean iguales aplicando la fórmula de Friedman. Para un texto en español, el IC típico es alrededor de 0.065, mientras que para un texto cifrado con una clave larga y aleatoria, el IC se acercará a 0.038.


def index_of_coincidence(text: str) -> float:
    """Calcula el Índice de Coincidencia (IC) de un texto dado.

    Args:
        text (str): El texto para el cual se desea calcular el IC.

    Returns:
        float: El Índice de Coincidencia del texto, que es una medida de la probabilidad
        de que dos letras seleccionadas al azar sean iguales.
    """
    counts = Counter(c for c in text.upper() if c.isalpha())
    N = sum(counts.values())
    if N <= 1:
        return 0.0
    numerator = sum(f * (f - 1) for f in counts.values())
    return numerator / (N * (N - 1))


# Ahora podemos juntar ambos métodos para obtener una mejor estimación de la longitud de la clave. Primero, utilizamos el método de Kasiski para identificar posibles longitudes de clave, y luego calculamos el IC para cada una de estas longitudes para determinar cuál es la más probable.


def vigenere_key_length_attack(cipher: str):
    """
    Realiza un ataque de análisis de frecuencia al cifrado Vigenère para intentar
    determinar la longitud de la clave.

    Args:
        cipher (str): El texto cifrado que se desea analizar.
    Returns:
        int: La longitud de clave más probable según el análisis.
    """
    candidates = kasiski_get_candidates(cipher)
    top_candidates = [c[0] for c in candidates[:10]]
    # print(f"Kasiski: {top_candidates}")
    THRESHOLD = 0.065
    best_len = 0
    best_ic = 0

    results = {}

    for length in top_candidates:
        # Verificamos el IC para cada longitud candidata dividiendo el texto en subsecuencias
        ics = []
        for i in range(length):
            subseq = cipher[i::length]
            ics.append(index_of_coincidence(subseq))
        avg_ic = sum(ics) / len(ics)

        results[length] = avg_ic
        # print(f"Longitud {length}: IC Promedio = {avg_ic:.4f}")
        if avg_ic > THRESHOLD:
            return length  # No queremos múltiplos de la longitud real

        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = length

    # print(f"\nLonguitud clave: {best_len} (IC: {best_ic:.4f})")
    return best_len


# Finalmente, una vez que tenemos una estimación de la longitud de la clave, podemos dividir el texto cifrado en grupos de letras correspondientes a cada letra de la clave y realizar un análisis de frecuencias en cada grupo para intentar deducir la letra de la clave correspondiente. Esto nos permitirá recuperar la clave completa y descifrar el mensaje original.
#
# Para ello, podemos usar la función `cesar_get_shift` definida anteriormente para determinar el desplazamiento de cada letra de la clave basándonos en que la letra más frecuente en cada grupo probablemente corresponda a la letra 'E' del alfabeto español.


def vigenere_attack(cipher: str) -> str:
    """
      This function performs an attack on a Vigenère cipher by first determining the key
      length using the Kasiski examination, and then performing a frequency analysis
      attack on each sub-cipher to determine the most likely key.

    Args:
        cipher (str): The cipher text to attack
        language_frequences (dict[str, float], optional): The frequency table for the
        target language. Defaults to FREQ_ES.
        type (int, optional): The type of attack to use (0 for monoalphabetic cipher
        attack, 1 for Caesar cipher attack). Defaults to 0.

    Returns:
        str: The estimated key
    """
    # Tal y como definimos la función vignere solo procesa caracteres alfabéticos, por
    # lo que limpiamos el texto cifrado para quedarnos solo con las letras y
    # convertirlas a mayúsculas. Esto nos asegurará que el análisis de frecuencias se
    # realice correctamente.
    clean_cipher = "".join(c for c in cipher.upper() if c.isalpha())
    if not clean_cipher:
        raise ValueError("El texto cifrado no contiene caracteres alfabéticos.")

    key_length = vigenere_key_length_attack(clean_cipher)
    key: str = ""
    for i in range(key_length):
        sub_cipher: str = "".join(
            clean_cipher[j] for j in range(i, len(clean_cipher), key_length)
        )
        key += chr(cesar_get_shift(sub_cipher) + ord("A"))

    return key


# # 2. Cifrados Modernos

# A continuación, implementaremos ataques a cifrados modernos, como el AES en modo CBC y el ataque por nonce reutilizado en cifrados de flujo. Estos ataques aprovechan vulnerabilidades específicas en la implementación de los cifrados modernos para recuperar información sin necesidad de conocer la clave de cifrado.

# ## AES-CBC

# ### Implementación del Oráculo de Padding

# En esta sección, implementaremos un ataque de padding oracle simulado en el modo de cifrado AES en CBC. Este tipo de ataque aprovecha la información que se puede obtener al intentar descifrar un mensaje con un padding incorrecto, lo que permite a un atacante recuperar el mensaje original sin conocer la clave de cifrado.


class PaddingOracle:
    def __init__(self, key: bytes):
        self.__key = key
        self.block_size = AES.block_size

    def check_padding(self, ciphertext: bytes, iv: bytes) -> bool:
        """
        Simula un servidor que descifra y solo indica si el padding es válido.
        VULNERABILIDAD: Revelar si el padding falló permite reconstruir el mensaje.
        Args:
            ciphertext (bytes): El bloque cifrado que se desea verificar.
            iv (bytes): El vector de inicialización utilizado para el cifrado.
        Returns:
            bool: True si el padding es correcto, False si el padding es incorrecto.
        """
        cipher = AES.new(self.__key, AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(ciphertext)

        try:
            # Si el padding es correcto, unpad no lanza excepción
            unpad(decrypted_data, self.block_size)
            return True
        except ValueError:
            # Padding incorrecto
            return False


# En este caso el oráculo solo nos dirá si el padding es correcto o no, lo que nos permitirá deducir información sobre el mensaje cifrado y eventualmente recuperar el mensaje original.

# ### Ataque a un bloque específico


def attack_single_block(c_target: bytes, c_prev: bytes, oracle: PaddingOracle) -> bytes:
    """
    Ataca un bloque específico (c_target) usando el bloque anterior (c_prev).
    Args:
        c_target (bytes): El bloque cifrado que se desea atacar.
        c_prev (bytes): El bloque cifrado anterior a c_target (o IV si es el primer bloque).
        oracle (PaddingOracle): La instancia del oracle de padding que se utilizará
    Returns:
        bytes: El bloque de texto plano correspondiente a c_target.
    """
    block_size = 16
    intermediate = [0] * block_size
    plaintext = [0] * block_size

    # Atacamos desde el último byte (índice 15) hasta el primero (0)
    for i in range(block_size - 1, -1, -1):
        expected_padding = block_size - i

        # Preparamos un bloque anterior falso (modified_prev)
        # Los bytes ya adivinados se ajustan para el nuevo padding
        prefix = [0] * i
        suffix = []
        for j in range(i + 1, block_size):
            suffix.append(intermediate[j] ^ expected_padding)

        found: bool = False
        for val in range(256):
            test_iv_bytes = bytes(prefix + [val] + suffix)

            if oracle.check_padding(c_target, iv=test_iv_bytes):
                intermediate[i] = val ^ expected_padding
                plaintext[i] = intermediate[i] ^ c_prev[i]
                found = True
                break

        if not found:
            print(f"Error: No se encontró byte válido para la posición {i}")

    return bytes(plaintext)


# Finalmente, implementaremos el ataque de padding oracle para recuperar un bloque específico del mensaje cifrado. Este ataque se basa en modificar el bloque anterior al bloque objetivo y observar las respuestas del oráculo para deducir el contenido del bloque objetivo.

# 1. Setup
key = get_random_bytes(16)
IV = get_random_bytes(16)
# Usamos un mensaje largo para tener 2 bloques
mensaje_secreto = b"ESTE ES UN MENSAJE SECRETO"

cipher = AES.new(key, AES.MODE_CBC, iv=IV)
ciphertext_original = cipher.encrypt(pad(mensaje_secreto, AES.block_size))
oracle = PaddingOracle(key)

print(f"Mensaje cifrado (hex): {ciphertext_original.hex()}")
print(f"Longitud cifrado: {len(ciphertext_original)} bytes")

# 2. Dividir en bloques de 16 bytes
blocks = [
    ciphertext_original[i : i + 16] for i in range(0, len(ciphertext_original), 16)
]
# Insertamos el IV al principio porque sirve como "bloque previo" para el primer bloque cifrado
blocks.insert(0, IV)

recovered_message = b""

# 3. Bucle Principal: Atacar bloque a bloque
# Empezamos desde el bloque 1 (el cifrado real) usando el bloque anterior como IV
for i in range(1, len(blocks)):
    c_target = blocks[i]  # El bloque que queremos descifrar
    c_prev = blocks[i - 1]  # El bloque anterior (actúa como IV en CBC)

    print(f"Atacando bloque {i}...")
    recovered_block = attack_single_block(c_target, c_prev, oracle)
    print(f" -> Bloque descifrado: {recovered_block}")
    recovered_message += recovered_block

# 4. Resultado final (Quitamos el padding manualmente para ver que es perfecto)
print("\n--- ATAQUE COMPLETADO ---")
print(f"Mensaje recuperado (con padding): {recovered_message}")
try:
    print(f"Mensaje final: {unpad(recovered_message, 16).decode()}")
except:
    print("Error al quitar padding final (algo falló en el ataque)")


# ## AES-GCM


# --- 1. ESCENARIO (LA VÍCTIMA) ---
# La víctima usa AES-GCM, que es muy seguro...
# PERO comete el error fatal de "hardcodear" el nonce.
key = get_random_bytes(32)  # Clave segura de 256 bits
FIXED_NONCE = b"\x00" * 12  # ¡ERROR CRÍTICO! Nonce fijo (o reutilizado)


def victim_encrypt(message: str):
    cipher = AES.new(key, AES.MODE_GCM, nonce=FIXED_NONCE)
    ciphertext, _ = cipher.encrypt_and_digest(message.encode())
    return ciphertext


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Realiza XOR byte a byte entre dos cadenas de bytes"""
    return bytes(x ^ y for x, y in zip(a, b))


def crib_drag_visual(xor_data: bytes, crib: str):
    """
    Arrastra una palabra probable (crib) sobre el XOR de los textos
    para ver si revela algo legible en el otro mensaje.
    """
    crib_bytes = crib.encode()
    print(f"Arrastrando la palabra probable: '{crib}'\n")

    for i in range(len(xor_data) - len(crib_bytes) + 1):
        # Extraemos el trozo del XOR en la posición actual
        chunk = xor_data[i : i + len(crib_bytes)]

        # Aplicamos la suposición: (P1^P2) ^ Crib
        try:
            potential_text = xor_bytes(chunk, crib_bytes).decode()
        except:
            potential_text = "?????"  # Caracteres no imprimibles

        # Visualización tipo Matrix
        padding = " " * i
        print(f"Pos {i:02}: {padding} -> Revela: '{potential_text}'")


# Qiskit imports
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit.circuit.library import DraperQFTAdder, MCMTGate, ZGate
from qiskit_aer import AerSimulator

# ==========================================
# 1. CLASE GROVER OPTIMIZADA
# ==========================================
class GroverUI:
    def __init__(self, oracle, num_solutions=1, state_preparation=None, search_space_size=16, diffusion_registers=None):
        self.oracle = oracle
        self.num_qubits = oracle.num_qubits
        self.num_solutions = num_solutions
        self.simulator = AerSimulator()
        self.diffusion_registers = diffusion_registers or [list(range(self.num_qubits))]
        
        if state_preparation is None:
            qc = QuantumCircuit(self.num_qubits)
            qc.h(range(self.num_qubits))
            self.state_preparation = qc
            self.search_space_size = 2**self.num_qubits
        else:
            self.state_preparation = state_preparation
            self.search_space_size = search_space_size

        theta = math.asin(math.sqrt(self.num_solutions / self.search_space_size))
        self.optimal_iterations = math.floor(math.pi / (4 * theta))

    def _build_diffuser(self) -> QuantumCircuit:
        qc = QuantumCircuit(self.num_qubits, name="Diffuser")
        qc.compose(self.state_preparation.inverse(), inplace=True)

        for reg in self.diffusion_registers:
            qc.x(reg)
            num_controls = len(reg) - 1
            if num_controls > 0:
                qc.compose(MCMTGate(ZGate(), num_controls, 1), qubits=reg, inplace=True)
            else:
                qc.z(reg[0])
            qc.x(reg)
            
        qc.compose(self.state_preparation, inplace=True)
        qc.global_phase = math.pi * len(self.diffusion_registers)
        return qc

    def build_circuit(self) -> QuantumCircuit:
        qr = QuantumRegister(self.num_qubits, name="q")
        cr = ClassicalRegister(self.num_qubits, name="c")
        qc = QuantumCircuit(qr, cr)

        qc.compose(self.state_preparation, inplace=True)
        diffuser = self._build_diffuser()
        
        for _ in range(self.optimal_iterations):
            qc.compose(self.oracle, inplace=True)
            qc.compose(diffuser, inplace=True)
            qc.barrier()

        qc.measure(qr, cr)
        return qc

    def search(self, shots=1024):
        qc = self.build_circuit()
        compiled_circuit = transpile(qc, self.simulator)
        job = self.simulator.run(compiled_circuit, shots=shots)
        return job.result().get_counts()



# Preparación de estado y oráculo para Cifrado César
def caesar_state_prep(P0_val, P1_val, num_bits=4):
    K = QuantumRegister(num_bits, "k")
    P0 = QuantumRegister(num_bits, "p0")
    P1 = QuantumRegister(num_bits, "p1")
    C = QuantumRegister(2, "cout")
    qc = QuantumCircuit(K, P0, P1, C)
    qc.h(K)
    for i in range(num_bits):
        if (P0_val >> i) & 1: qc.x(P0[i])
        if (P1_val >> i) & 1: qc.x(P1[i])
    return qc

def caesar_oracle(C0_val, C1_val, num_bits=4):
    K = QuantumRegister(num_bits, "k")
    P0 = QuantumRegister(num_bits, "p0")
    P1 = QuantumRegister(num_bits, "p1")
    C = QuantumRegister(2, "cout")
    qc = QuantumCircuit(K, P0, P1, C)

    adder = DraperQFTAdder(num_bits, kind="half")
    qc.append(adder, list(K) + list(P0) + [C[0]])
    qc.append(adder, list(K) + list(P1) + [C[1]])

    for i in range(num_bits):
        if not ((C0_val >> i) & 1): qc.x(P0[i])
        if not ((C1_val >> i) & 1): qc.x(P1[i])

    p_qubits = list(P0) + list(P1)
    qc.compose(MCMTGate(ZGate(), len(p_qubits) - 1, 1), qubits=p_qubits, inplace=True)

    for i in range(num_bits):
        if not ((C0_val >> i) & 1): qc.x(P0[i])
        if not ((C1_val >> i) & 1): qc.x(P1[i])

    qc.append(adder.inverse(), list(K) + list(P1) + [C[1]])
    qc.append(adder.inverse(), list(K) + list(P0) + [C[0]])
    return qc


## Preparación de estado y oráculo para Vigenère
def vigenere_state_prep(P_vals, num_bits=4):
    n_blocks = len(P_vals) # Calculamos la longitud (n) dinámicamente
    
    K = [QuantumRegister(num_bits, f"k{i}") for i in range(n_blocks)]
    P = [QuantumRegister(num_bits, f"p{i}") for i in range(n_blocks)]
    C = QuantumRegister(n_blocks, "cout")
    qc = QuantumCircuit(*K, *P, C)
    
    for i in range(n_blocks):
        qc.h(K[i])
        for bit in range(num_bits):
            if (P_vals[i] >> bit) & 1: 
                qc.x(P[i][bit])
    return qc

def vigenere_oracle(C_vals, num_bits=4):
    n_blocks = len(C_vals) # Calculamos la longitud (n) dinámicamente
    
    K = [QuantumRegister(num_bits, f"k{i}") for i in range(n_blocks)]
    P = [QuantumRegister(num_bits, f"p{i}") for i in range(n_blocks)]
    C = QuantumRegister(n_blocks, "cout")
    qc = QuantumCircuit(*K, *P, C)
    
    adder = DraperQFTAdder(num_bits, kind="half")

    # 1. Sumas independientes
    for i in range(n_blocks):
        qc.append(adder, list(K[i]) + list(P[i]) + [C[i]])

    # 2 y 3. Verificación e Inversión de Fase
    for i in range(n_blocks):
        for bit in range(num_bits):
            if not ((C_vals[i] >> bit) & 1): 
                qc.x(P[i][bit])
                
        # El MCMTGate necesita (num_bits - 1) controles
        qc.compose(MCMTGate(ZGate(), num_bits - 1, 1), qubits=list(P[i]), inplace=True)
        
        for bit in range(num_bits):
            if not ((C_vals[i] >> bit) & 1): 
                qc.x(P[i][bit])

    # 4. Deshacer el cómputo (Uncompute)
    for i in range(n_blocks):
        qc.append(adder.inverse(), list(K[i]) + list(P[i]) + [C[i]])
        
    return qc