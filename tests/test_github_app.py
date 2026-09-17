import os
import unittest

from identity.github_app import GitHubAppAuthError, load_config_from_env


class GitHubAppFailClosed(unittest.TestCase):
    def setUp(self):
        for key in (
            "GITHUB_APP_ID",
            "GITHUB_APP_INSTALLATION_ID",
            "GITHUB_APP_PRIVATE_KEY",
            "GITHUB_APP_PRIVATE_KEY_PATH",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "GITHUB_ALLOW_PAT_FALLBACK",
            "PRODUCTION",
        ):
            os.environ.pop(key, None)

    def test_production_fails_closed(self):
        os.environ["PRODUCTION"] = "1"
        with self.assertRaises(GitHubAppAuthError):
            load_config_from_env()

    def test_lab_pat_fallback_flag(self):
        os.environ["PRODUCTION"] = "0"
        os.environ["GITHUB_ALLOW_PAT_FALLBACK"] = "1"
        cfg = load_config_from_env()
        self.assertTrue(cfg.allow_pat_fallback)


if __name__ == "__main__":
    unittest.main()
