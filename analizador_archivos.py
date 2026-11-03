"""
Analizador de archivos (educativo) - solo biblioteca estándar.
Uso:  python analizador_archivos.py <archivo> [reporte.txt]
Los archivos analizados solo se leen; nunca se ejecutan ni se modifican.
Las reglas son educativas: un indicador no significa que sea malicioso.
"""
import hashlib
import os
import sys


# ======================= ERRORES =======================
class AnalizadorError(Exception):
    """Error base."""


class RutaInvalidaError(AnalizadorError):
    """Ruta vacía, inválida o que no es un archivo."""


class ArchivoNoEncontradoError(AnalizadorError):
    """El archivo no existe."""


class ErrorLecturaError(AnalizadorError):
    """No se pudo leer el archivo."""


# ======================= INFO DEL ARCHIVO =======================
def validar_ruta(ruta):
    if not isinstance(ruta, str) or not ruta.strip():
        raise RutaInvalidaError("La ruta está vacía o no es texto.")
    if "\0" in ruta:
        raise RutaInvalidaError("La ruta contiene caracteres inválidos.")
    if not os.path.exists(ruta):
        raise ArchivoNoEncontradoError(f"El archivo no existe: {ruta}")
    if not os.path.isfile(ruta):
        raise RutaInvalidaError(f"La ruta no es un archivo: {ruta}")


def obtener_info(ruta):
    validar_ruta(ruta)
    nombre = os.path.basename(ruta)
    return {
        "nombre": nombre,
        "extension": os.path.splitext(nombre)[1].lower() or "(sin extensión)",
        "tamano": os.path.getsize(ruta),
        "ruta": os.path.abspath(ruta),
    }


# ======================= HASH SHA-256 =======================
def calcular_sha256(ruta):
    validar_ruta(ruta)
    sha = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                sha.update(bloque)
    except OSError as e:
        raise ErrorLecturaError(f"No se pudo leer el archivo: {e}") from e
    return sha.hexdigest()


# ======================= INDICADORES =======================
# patrón (minúsculas): (descripción, puntos)
INDICADORES = {
    "os.system": ("Ejecución de comandos del sistema (Python)", 5),
    "subprocess": ("Creación de procesos (Python)", 4),
    "eval(": ("Evaluación dinámica de código", 4),
    "exec(": ("Ejecución dinámica de código", 4),
    "cmd.exe": ("Uso del intérprete de comandos de Windows", 3),
    "powershell": ("Uso de PowerShell", 3),
    "/bin/bash": ("Uso del shell de Unix", 3),
    "rm -rf": ("Comando de borrado recursivo", 5),
    "base64": ("Posible ofuscación de contenido", 2),
    "http://": ("Dirección web sin cifrar", 1),
}


def leer_contenido(ruta):
    validar_ruta(ruta)
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
    except OSError as e:
        raise ErrorLecturaError(f"No se pudo leer el archivo: {e}") from e
    return datos.decode("latin-1").lower()


def buscar_indicadores(ruta):
    contenido = leer_contenido(ruta)
    encontrados = []
    for patron, (descripcion, puntos) in INDICADORES.items():
        veces = contenido.count(patron)
        if veces > 0:
            encontrados.append({"patron": patron, "descripcion": descripcion,
                                "puntos": puntos, "apariciones": veces})
    return encontrados


# ======================= RIESGO =======================
# Cada indicador suma sus puntos una vez. 0-4 BAJO, 5-9 MEDIO, 10+ ALTO.
def calcular_puntuacion(indicadores):
    return sum(i["puntos"] for i in indicadores)


def clasificar_riesgo(puntuacion):
    if puntuacion >= 10:
        return "ALTO"
    if puntuacion >= 5:
        return "MEDIO"
    return "BAJO"


# ======================= ANÁLISIS =======================
def analizar_archivo(ruta):
    info = obtener_info(ruta)
    sha256 = calcular_sha256(ruta)
    indicadores = buscar_indicadores(ruta)
    puntuacion = calcular_puntuacion(indicadores)
    return {"info": info, "sha256": sha256, "indicadores": indicadores,
            "puntuacion": puntuacion, "nivel": clasificar_riesgo(puntuacion)}


# ======================= REPORTE =======================
def generar_texto(resultado):
    info = resultado["info"]
    lineas = [
        "=" * 50, "REPORTE DE ANÁLISIS DE ARCHIVO", "=" * 50,
        f"Nombre:     {info['nombre']}",
        f"Extensión:  {info['extension']}",
        f"Tamaño:     {info['tamano']} bytes",
        f"Ruta:       {info['ruta']}",
        f"SHA-256:    {resultado['sha256']}",
        "", "Indicadores encontrados:",
    ]
    if resultado["indicadores"]:
        for i in resultado["indicadores"]:
            lineas.append(f"  - '{i['patron']}' x{i['apariciones']} "
                          f"(+{i['puntos']}): {i['descripcion']}")
    else:
        lineas.append("  (ninguno)")
    lineas += [
        "", f"Puntuación: {resultado['puntuacion']}",
        f"Nivel de riesgo: {resultado['nivel']}", "",
        "Nota: reglas educativas. Un indicador sospechoso no significa "
        "que el archivo sea malicioso.",
    ]
    return "\n".join(lineas)


def mostrar_reporte(resultado):
    print(generar_texto(resultado))


def exportar_txt(resultado, ruta_salida="reporte.txt"):
    try:
        with open(ruta_salida, "w", encoding="utf-8") as f:
            f.write(generar_texto(resultado) + "\n")
    except OSError as e:
        raise AnalizadorError(f"No se pudo escribir el reporte: {e}") from e
    return ruta_salida


# ======================= PROGRAMA PRINCIPAL =======================
def main():
    if len(sys.argv) < 2:
        print("Uso: python analizador_archivos.py <archivo> [reporte.txt]")
        return 1
    salida = sys.argv[2] if len(sys.argv) > 2 else "reporte.txt"
    try:
        resultado = analizar_archivo(sys.argv[1])
        mostrar_reporte(resultado)
        print(f"\nReporte exportado en: {exportar_txt(resultado, salida)}")
    except AnalizadorError as e:
        print(f"Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
