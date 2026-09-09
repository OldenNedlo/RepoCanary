import json,tempfile
from pathlib import Path
import unittest
from repocanary.scanner import scan_repository,should_fail

class RepoCanaryTests(unittest.TestCase):
    def repo(self):
        temp=tempfile.TemporaryDirectory(); root=Path(temp.name)
        for name in ["LICENSE","SECURITY.md","CONTRIBUTING.md","CODE_OF_CONDUCT.md"]:
            (root/name).write_text("ok\n",encoding="utf-8")
        return temp,root
    def test_clean_repo(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        self.assertEqual([],scan_repository(root).findings)
    def test_sensitive_file_is_high(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        (root/".env").write_text("EXAMPLE=value\n",encoding="utf-8")
        result=scan_repository(root)
        self.assertTrue(any(x.check=="sensitive-filename" for x in result.findings))
        self.assertTrue(should_fail(result,"high"))
    def test_broken_markdown_link(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        (root/"README.md").write_text("[bad](missing.md)\n",encoding="utf-8")
        self.assertTrue(any(x.check=="markdown-link" for x in scan_repository(root).findings))
    def test_moving_workflow_reference(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        workflow=root/".github"/"workflows"; workflow.mkdir(parents=True)
        (workflow/"ci.yml").write_text("steps:\n  - uses: actions/checkout@main\n",encoding="utf-8")
        self.assertTrue(any(x.check=="workflow-ref" for x in scan_repository(root).findings))
    def test_unconstrained_requirement(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        (root/"requirements.txt").write_text("requests\npytest>=8\n",encoding="utf-8")
        self.assertEqual(1,len([x for x in scan_repository(root).findings if x.check=="python-requirement"]))
    def test_ignore_pattern(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        (root/".env").write_text("ignored=true\n",encoding="utf-8")
        self.assertFalse(any(x.check=="sensitive-filename" for x in scan_repository(root,ignore_patterns=(".env",)).findings))
    def test_sarif_output(self):
        temp,root=self.repo(); self.addCleanup(temp.cleanup)
        (root/".env").write_text("EXAMPLE=value\n",encoding="utf-8")
        data=json.loads(scan_repository(root).to_sarif())
        self.assertEqual("2.1.0",data["version"])
        self.assertEqual("RepoCanary",data["runs"][0]["tool"]["driver"]["name"])

if __name__=="__main__": unittest.main()
