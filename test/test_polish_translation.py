"""Polish UI strings cover every English key and keep printf placeholders."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_i18n import parse_yaml_file

# A conversion specification, not a literal percent such as "Hide Battery %".
SPEC_RE = re.compile(r"%(?:[-+0 #]*\d*(?:\.\d+)?(?:hh|ll|h|l|j|z|t)?)?[diufFeEgGxXoscp]")

# Strings the audit called out, plus terminology this pass removed.
DENY = (
    "Sprawdź uaktualnia",
    "Uaktualn",
    "uaktualn",
    "spróbój",
    "paragraf",
    "Obrazki",
    "Skórka",
    "OPDS Browser",
    "Bootowanie",
    "Zrobione",
    "Nast. str.",
)


def specs(value: str):
    found = []
    i = 0
    while i < len(value):
        if value[i] != "%":
            i += 1
            continue
        if i + 1 < len(value) and value[i + 1] == "%":
            i += 2
            continue
        match = SPEC_RE.match(value, i)
        if not match:
            i += 1
            continue
        found.append(match.group(0))
        i = match.end()
    return found


class PolishTranslationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.english = parse_yaml_file(str(ROOT / "lib/I18n/translations/english.yaml"))
        cls.polish = parse_yaml_file(str(ROOT / "lib/I18n/translations/polish.yaml"))

    def test_metadata(self):
        self.assertEqual(self.polish["_language_name"], "Polski")
        self.assertEqual(self.polish["_language_code"], "PL")
        self.assertEqual(self.polish["_bcp47"], "pl")

    def test_every_english_key_is_translated(self):
        english_keys = [key for key in self.english if key.startswith("STR_")]
        polish_keys = [key for key in self.polish if key.startswith("STR_")]
        self.assertEqual(polish_keys, english_keys)
        for key in english_keys:
            english = self.english[key]
            polish = self.polish[key]
            self.assertTrue(polish.strip(), key)
            # Prefixes such as "do " keep the edge space the caller concatenates.
            if english == english.strip():
                self.assertEqual(polish, polish.strip(), key)

    def test_placeholders_match_english(self):
        for key, english in self.english.items():
            if not key.startswith("STR_"):
                continue
            self.assertEqual(specs(english), specs(self.polish[key]), key)

    def test_removed_wording_stays_gone(self):
        blob = "\n".join(self.polish.values())
        for phrase in DENY:
            self.assertNotIn(phrase, blob)

    def test_proper_names_stay_in_english(self):
        self.assertIn("OPDS", self.polish["STR_OPDS_BROWSER"])
        self.assertIn("KOReader", self.polish["STR_KOREADER_SETUP_HINT"])
        self.assertIn("Read", self.polish["STR_MOVE_FINISHED_TO_READ"])
        self.assertEqual(self.polish["STR_CROSSPOINT"], "CrossPoint")
        self.assertEqual(self.polish["STR_KOSYNC_SERVER"], "KoSync")

    def test_number_bearing_labels_do_not_assume_one_plural(self):
        # The generator has no plural forms. A label in front of the count stays
        # grammatical for 1, 2, and 5. An inflected noun after the number does not.
        self.assertEqual(self.polish["STR_NETWORKS_FOUND"], "Sieci: %zu")
        self.assertEqual(self.polish["STR_LIBRARY_POSITION"], "książki: %d/%d")
        self.assertEqual(self.polish["STR_LIBRARY_GROUP_POSITION"], "grupy: %d/%d")
        self.assertEqual(self.polish["STR_OPDS_COPIES"], "dostępne: %d z %d")
        self.assertEqual(self.polish["STR_ITEMS_REMOVED"], "usunięto")
        # After the count, and also the whole BMP failure popup. A past form
        # with no noun stays grammatical for 1, 2, and 5.
        self.assertEqual(self.polish["STR_FAILED_LOWER"], "nie udało się")
        self.assertEqual(self.polish["STR_OPDS_HOLDS"], "%d w kolejce")
        self.assertEqual(self.polish["STR_PAGES_SEPARATOR"], " str.  |  ")


if __name__ == "__main__":
    unittest.main()
