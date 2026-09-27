import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class IntentDisplayTemplateTests(unittest.TestCase):
    def test_compact_display_omits_commitment_metadata_and_duplicate_recipient(self):
        from app.presentation import render_intent_fields
        fields = dict(render_intent_fields("transfer", {"beneficiary_id": 17}, {
            "referent_commitments": [{"type": "beneficiary", "version": 2,
                "content_sha256": "hidden", "content": {
                    "name": "Alice Example", "bank": "Study Bank", "account_number": "00123456"}}]}))
        self.assertNotIn("Destination account", fields)
        self.assertNotIn("Beneficiary name", fields)
        self.assertNotIn("Referent commitments", fields)
        template = (ROOT / "app/templates/base.html").read_text()
        self.assertIn("skipIdx.add(recipientIdx)", template)
    def test_webauthn_modal_has_explicit_safe_complete_intent_display(self) -> None:
        template = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")

        self.assertIn('id="poia-modal"', template)
        self.assertIn('id="poia-sign"', template)
        self.assertIn('role="dialog"', template)
        self.assertIn('id="poia-cancel">Decline operation</button>', template)
        self.assertNotIn("handlePanelTap", template)
        self.assertNotIn("Tap the intent panel", template)
        self.assertIn("startPasskey()", template)
        self.assertIn("appendIntentSection(container, 'Scope'", template)
        self.assertIn("appendIntentSection(container, 'Authorization context'", template)
        self.assertIn("appendIntentSection(container, 'Constraints'", template)
        self.assertIn("poiaSummary.replaceChildren(container)", template)
        self.assertNotIn("poiaSummary.innerHTML", template)

    def test_intent_values_wrap_on_narrow_screens(self) -> None:
        stylesheet = (ROOT / "app" / "static" / "style.css").read_text(encoding="utf-8")

        self.assertIn(".intent-section dd", stylesheet)
        self.assertIn("overflow-wrap: anywhere", stylesheet)
        self.assertIn("@media (max-width: 560px)", stylesheet)

    def test_zt_selection_hides_browser_modal_with_webauthn_fallback(self) -> None:
        template = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
        stylesheet = (ROOT / "app" / "static" / "style.css").read_text(encoding="utf-8")

        self.assertIn("poia_zt_enabled'] %} poia-hidden", template)
        self.assertIn("poiaBackdrop?.classList.remove('poia-hidden')", template)
        self.assertIn(".poia-backdrop.poia-hidden", stylesheet)
        self.assertIn("display: none", stylesheet)


if __name__ == "__main__":
    unittest.main()
