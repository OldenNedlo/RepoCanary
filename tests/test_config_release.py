import json,tempfile
from pathlib import Path
import unittest
from repocanary.config import load_policy
from repocanary.release import release_check

class ConfigAndReleaseTests(unittest.TestCase):
    def test_policy_loading(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/".repocanary.json").write_text(json.dumps({"large_file_mib":4,"fail_on":"medium","ignore":["vendor/**"]}),encoding="utf-8")
            policy=load_policy(root)
            self.assertEqual((4,"medium",("vendor/**",)),(policy.large_file_mib,policy.fail_on,policy.ignore))
    def test_release_check_flags_missing_release_assets(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ["LICENSE","SECURITY.md","CONTRIBUTING.md","CODE_OF_CONDUCT.md"]:
                (root/name).write_text("ok\n",encoding="utf-8")
            checks={x.check for x in release_check(root).findings}
            self.assertIn("release-readiness",checks)
    def test_release_check_accepts_core_release_assets(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ["LICENSE","SECURITY.md","CONTRIBUTING.md","CODE_OF_CONDUCT.md","CHANGELOG.md"]:
                (root/name).write_text("ok\n",encoding="utf-8")
            (root/"tests").mkdir()
            (root/".github"/"workflows").mkdir(parents=True)
            (root/".github"/"workflows"/"ci.yml").write_text("name: CI\n",encoding="utf-8")
            (root/".github"/"PULL_REQUEST_TEMPLATE.md").write_text("template\n",encoding="utf-8")
            (root/".github"/"dependabot.yml").write_text("version: 2\nupdates: []\n",encoding="utf-8")
            (root/"pyproject.toml").write_text('[project]\nname="x"\nversion="1.0.0"\n',encoding="utf-8")
            result=release_check(root)
            self.assertFalse(any(x.check in {"release-readiness","release-version","maintainer-workflow","dependency-maintenance"} for x in result.findings))
if __name__=="__main__": unittest.main()
