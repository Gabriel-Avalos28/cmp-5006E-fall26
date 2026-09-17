# Semana 3 Studio: Modos de Operación y Mal Uso (Modes & Misuse)
## Guía Explicativa Detallada de Conceptos y Tareas

Este documento contiene un desglose completo y conceptual de todo lo aprendido e implementado durante el Studio de la Semana 3. El objetivo es proporcionar una base sólida para entender cómo funcionan los cifrados en la práctica y por qué la seguridad depende del **modo de operación** y no solo de la fuerza del algoritmo base.

---

## 1. La Gran Lección: Primitiva vs. Modo de Operación

En criptografía moderna existen dos niveles esenciales:
1. **La Primitiva Criptográfica:** Es el algoritmo matemático fundamental, como **AES** (cifrado por bloques) o **SHA-256** (función hash). Estos algoritmos están diseñados para operar sobre tamaños de datos fijos (por ejemplo, bloques de 16 bytes para AES). Hasta donde sabemos hoy, estas primitivas son matemáticamente seguras e inviolables por fuerza bruta práctica.
2. **El Modo de Operación o Construcción:** Es la receta o arquitectura que envuelve a la primitiva para permitir procesar datos de longitud arbitraria (archivos grandes, mensajes de red, flujos de datos en tiempo real).

> **Conclusión fundamental:** En este studio, **ningún ataque rompió AES ni SHA-256**. Todos los ataques tuvieron éxito exclusivamente debido al **mal uso (misuse)** del modo de operación o de la construcción empleada.

---

## 2. Tarea 1: Fuga de Estructura en ECB (ECB vs. CBC)

### El Concepto
* **ECB (Electronic Codebook):** Es la forma más primitiva e intuitiva de cifrar un mensaje largo. Divide el mensaje en bloques del tamaño soportado por el cifrador (por ejemplo, 16 bytes o 3 bytes en nuestro ejercicio) y cifra cada bloque **de forma independiente y determinista** con la misma clave:
  $$\text{Bloque Cifrado}_i = E_K(\text{Bloque Plano}_i)$$
* **La Falla:** Al ser determinista y aislado, **bloques de texto plano idénticos siempre producen bloques de texto cifrado idénticos**.
* **La Fuga de Estructura:** Si los datos tienen patrones repetitivos (como un archivo BMP o una imagen con regiones de colores uniformes), el texto cifrado preservará los mismos patrones y siluetas. Aunque no puedas leer los bytes exactos, puedes "ver" la información.

### Lo que se Hizo en el Código
En `starter.py`, implementamos la función `ecb_leak_count`:
```python
def ecb_leak_count(image: bytes, key: bytes) -> int:
    ciphertext = ecb_encrypt(image, key)
    return distinct_blocks(ciphertext)
```
1. Ciframos la imagen completa en modo ECB usando `ecb_encrypt(image, key)`.
2. Usamos `distinct_blocks(...)` para contar cuántos bloques únicos o diferentes componen el texto cifrado resultante.

### Resultado y Análisis
* **Resultado:** Nos devolvió exactamente **2 bloques distintos**.
* **¿Por qué 2?** Porque la imagen de prueba solo contiene dos regiones de color uniformes (el fondo y la figura del pingüino). Por ende, en texto plano solo existen dos bloques distintos repetidos a lo largo de toda la imagen. ECB produjo exactamente 2 bloques cifrados distintos distribuidos en la misma posición, filtrando la imagen al 100%.
* **Contraste con CBC (Cipher Block Chaining):** En CBC, cada bloque de texto plano se combina con una operación `XOR` con el bloque cifrado anterior antes de pasar por el cifrador:
  $$\text{Bloque Cifrado}_i = E_K(\text{Bloque Plano}_i \oplus \text{Bloque Cifrado}_{i-1})$$
  Esta dependencia en cadena rompe los patrones repetitivos. En el mismo archivo de 96 bloques totales, CBC produce **96 bloques únicos**, convirtiendo la imagen en ruido pseudoaleatorio indistinguible.

---

## 3. Tarea 2: Reuso de Nonce en Modo CTR (Two-Time Pad)

### El Concepto
* **CTR (Counter Mode):** Convierte un cifrador de bloques en un cifrador de flujo (*stream cipher*). No cifra directamente los datos. En su lugar, cifra una secuencia compuesta por un número que solo se usa una vez (**nonce**) concatenado con un contador incremental:
  $$\text{Keystream} = E_K(\text{Nonce} \parallel 0) \parallel E_K(\text{Nonce} \parallel 1) \parallel \dots$$
  Luego, el texto cifrado se genera aplicando un `XOR` bit a bit entre el mensaje plano y este flujo pseudoaleatorio:
  $$C = M \oplus \text{Keystream}$$
* **La Propiedad Matemática de XOR:**
  * $A \oplus A = 0$ (cualquier valor contra sí mismo se anula).
  * $A \oplus 0 = A$.
  * La operación es asociativa y conmutativa.
* **La Falla (Reuso de Nonce):** Si se cifran dos mensajes diferentes ($M_1$ y $M_2$) con la **misma clave y el mismo nonce**, ambos mensajes usarán exactamente el **mismo Keystream**.

### Lo que se Hizo en el Código
En `starter.py`, implementamos `recover_second_plaintext`:
```python
def recover_second_plaintext(c1: bytes, c2: bytes, known_m1: bytes) -> bytes:
    # c1 ⊕ c2 == (m1 ⊕ keystream) ⊕ (m2 ⊕ keystream) == m1 ⊕ m2
    # Por lo tanto: (c1 ⊕ c2) ⊕ m1 == (m1 ⊕ m2) ⊕ m1 == m2
    return xor(xor(c1, c2), known_m1)
```

### Resultado y Análisis
* **Resultado:** Recuperamos exitosamente el texto plano: `b'the quarterly meeting moved to three pm'`.
* **¿Por qué funciona?** Al hacer `XOR` entre ambos textos cifrados ($C_1 \oplus C_2$), el keystream compartido se cancela por completo, dejando al descubierto $M_1 \oplus M_2$. Al tener conocimiento de uno de los mensajes ($M_1$), simplemente aplicamos nuevamente `XOR` con $M_1$ y obtenemos $M_2$ de manera inmediata, idéntico a romper un *One-Time Pad* reutilizado (Two-Time Pad).

---

## 4. Tarea 3: Ataque de Extensión de Longitud en MACs Ingenuos

### El Concepto
* **Construcción Merkle–Damgård:** La mayoría de funciones hash tradicionales (MD5, SHA-1, SHA-256) procesan mensajes en bloques secuenciales. Toman un estado interno inicial ($IV$), procesan un bloque junto con ese estado para generar un nuevo estado interno, y repiten hasta el final. El *digest* (la salida del hash) **es literalmente el estado interno final**.
* **El MAC Ingenuo ($H(\text{secreto} \parallel \text{mensaje})$):** Para autenticar un mensaje, alguien podría pensar en concatenar una clave secreta al inicio del mensaje y calcular su hash.
* **La Falla (Length Extension Attack):** Si un atacante conoce el mensaje y su tag (el digest del hash), y conoce (o adivina) la **longitud del secreto**:
  1. El atacante conoce el estado interno exacto al final del mensaje (porque es el tag).
  2. El atacante puede calcular el relleno (*padding*) que la función hash agregó internamente.
  3. El atacante puede "despertar" o reanudar el cálculo del hash partiendo del tag como nuevo $IV$, procesando un texto adicional (*extensión maliciosa*) sin haber visto jamás la clave secreta.

### Lo que se Hizo en el Código
En `starter.py`, implementamos `forge_extension`:
```python
def forge_extension(observed_msg: bytes, observed_tag: int, secret_len: int,
                    extension: bytes):
    total = secret_len + len(observed_msg)
    pad = bytes((-total) % 4)                             # Replica el padding a bloques de 4 bytes
    forged_msg = observed_msg + pad + extension           # Construye el mensaje falsificado
    forged_tag = md_hash(extension, iv=observed_tag)      # Reanuda el hash desde el estado previo
    return forged_msg, forged_tag
```

### Resultado y Análisis
* **Resultado:** Generamos exitosamente el mensaje:
  `b'amount=100&to=alice\x00\x00&to=attacker'` con un tag que el servidor validó como 100% auténtico (`valid? True`).
* **¿Por qué HMAC previene esto?** HMAC no es un simple hash concatenado; es una construcción anidada:
  $$\text{HMAC}(K, M) = H((K \oplus \text{opad}) \parallel H((K \oplus \text{ipad}) \parallel M))$$
  Al aplicar un segundo hash exterior a la salida del hash interior, el estado interno del hash del mensaje queda oculto y sellado. Un atacante no puede reanudar el hash interior porque no tiene acceso a su estado final sin romper la capa exterior.

---

## 5. Matriz de Control (Control Scorecard: Eje 2)

El concepto clave del **Scorecard** en seguridad es que toda afirmación de seguridad debe formularse como:
$$\text{Garantía } + \text{ Condición de la que depende}$$

| Construcción | Garantía Real | Condición Estricta / Falla | Clasificación |
|---|---|---|---|
| **ECB Mode** | Confidencialidad sobre bloques individuales aislados. | **Falla:** Filtra la estructura global del mensaje (bloques idénticos dan salidas idénticas). | Mal uso (*Misuse*) |
| **CTR Mode** | Confidencialidad total del mensaje completo. | **Condición:** El par `(Key, Nonce)` no debe repetirse jamás. Si el nonce se repite, se cancela el keystream (Two-Time Pad). | Mal uso (*Misuse*) |
| **$H(\text{secreto} \parallel \text{msg})$** | Parece garantizar integridad y autenticidad. | **Falla:** Vulnerable a ataques de extensión de longitud sin conocer el secreto. | Mal uso (*Misuse*) |
| **HMAC** | Autenticidad e integridad verificables; inmune a extensión de longitud. | **Condición:** Requiere que la clave simétrica permanezca en secreto. | Seguro bajo su condición |

---

## 6. Pregunta de Reflexión: ¿Qué pasa si reutilizamos la LLAVE pero el NONCE siempre es único en CTR?

* **Pregunta:** Si ciframos un millón de mensajes con la **misma clave**, pero garantizamos que **cada mensaje usa un nonce completamente único y diferente**, ¿sigue siendo seguro el modo CTR?
* **Respuesta:** **Sí, es 100% seguro.**
* **Justificación Técnica:** La entrada al cifrador de bloques para generar el keystream es $(Nonce \parallel Contador)$. Mientras el nonce sea distinto para cada mensaje, las entradas al cifrador jamás colisionarán, produciendo flujos de keystream completamente disjuntos y únicos. La condición crítica de CTR no prohíbe reusar la clave, sino reusar la pareja `(Clave, Nonce)`.
