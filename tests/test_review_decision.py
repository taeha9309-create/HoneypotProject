"""Synthetic Streamlit decision tests using temporary registries."""
from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from streamlit.testing.v1 import AppTest
from ml.analysis import candidate_registry as R


class ReviewDecisionTests(unittest.TestCase):
    def test_required_fields_and_decision_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            registry=Path(directory)/"registry.db"
            with closing(R.open_registry(registry)) as conn:
                conn.execute("INSERT INTO candidates(id,payload,status) VALUES ('test','{}','proposed')")
                conn.commit()
            script = (
                "import sys\nfrom pathlib import Path\n"
                f"sys.path.insert(0, {str(Path.cwd()/'streamlit_app')!r})\n"
                "from contextlib import closing\nfrom ml.analysis import candidate_registry as R\n"
                "import review_decision\n"
                f"registry=Path({str(registry)!r})\n"
                "with closing(R.open_registry(registry)) as conn:\n"
                " item=R.read_candidate(conn,'test')\n"
                "item['id']='test'\nreview_decision.render(item,registry)\n"
            )
            app=AppTest.from_string(script,default_timeout=20).run()
            self.assertFalse(app.exception)
            app.button[0].click().run()
            self.assertTrue(app.warning)
            app.text_input[0].set_value("synthetic reviewer")
            app.text_area[0].set_value("synthetic rejection")
            app.radio[0].set_value("거부")
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(app.button),0)
            with closing(R.open_registry(registry)) as conn:
                saved=R.read_candidate(conn,"test")
            self.assertEqual(saved["status"],"rejected")
            self.assertEqual(saved["reason"],"synthetic rejection")
