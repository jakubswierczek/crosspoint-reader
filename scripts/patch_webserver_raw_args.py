"""Parse the query string before a raw WebDAV PUT body is consumed.

Arduino-ESP32's WebServer calls canRaw() without _parseArguments(), so
hasArg("k") is empty for PUT and the access code in the URL is invisible.
"""

from pathlib import Path

Import("env")

MARKER = "/* CrossPoint: query string before raw body */"
OLD = """    if (!isForm && _currentHandler && _currentHandler->canRaw(*this, _currentUri)) {
      log_v("Parse raw");
"""
NEW = f"""    if (!isForm && _currentHandler && _currentHandler->canRaw(*this, _currentUri)) {{
      {MARKER}
      _parseArguments(searchStr);
      log_v("Parse raw");
"""


def patch_parsing(path: Path) -> None:
    text = path.read_text()
    if MARKER in text:
        return
    if OLD not in text:
        raise RuntimeError(f"WebServer Parsing.cpp has no raw-handler anchor: {path}")
    path.write_text(text.replace(OLD, NEW, 1))
    print(f"Patched raw query parsing: {path}")


framework = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif32"))
parsing = framework / "libraries" / "WebServer" / "src" / "Parsing.cpp"
if parsing.is_file():
    patch_parsing(parsing)
