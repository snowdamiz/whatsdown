import unittest

from prove_content_ingress import has_parser_refusal


class ParserRefusalTests(unittest.TestCase):
    def test_available_export_is_not_a_refused_import(self):
        diagnostics = [{
            "code": "E0034", "file": "main.mpl",
            "message": "`parse_store_request` is not exported by module `Mobile.Requests`; "
                       "available: parse_fanout_targets_request, parse_triple_payload_request",
        }]
        self.assertTrue(has_parser_refusal(diagnostics, "E0034", "Mobile.Requests",
                                           "parse_store_request", "main.mpl"))
        for exported in ("parse_fanout_targets_request", "parse_triple_payload_request"):
            with self.subTest(exported=exported):
                self.assertFalse(has_parser_refusal(diagnostics, "E0034", "Mobile.Requests",
                                                    exported, "main.mpl"))

    def test_private_import_must_name_the_target_module_and_source(self):
        diagnostics = [{
            "code": "E0035", "file": "main.mpl",
            "message": "`parse_store_request` is private in module `MobileCore`; "
                       "add `pub` to make it accessible",
        }]
        self.assertTrue(has_parser_refusal(diagnostics, "E0035", "MobileCore",
                                           "parse_store_request", "main.mpl"))
        self.assertFalse(has_parser_refusal(diagnostics, "E0035", "Mobile.Requests",
                                            "parse_store_request", "main.mpl"))
        self.assertFalse(has_parser_refusal(diagnostics, "E0035", "MobileCore",
                                            "parse_store_request", "other.mpl"))


if __name__ == "__main__":
    unittest.main()
