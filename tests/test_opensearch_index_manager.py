import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

sys.path.insert(
    0,
    str(
        PROJECT_ROOT / "src"
    ),
)


from opensearch_index_manager import (  # noqa: E402
    OpenSearchIndexManager,
    build_index_names,
)


class FakeClient:

    def __init__(self):
        self.indices = set()
        self.aliases = {}
        self.created = []
        self.actions = []

    def index_exists(
        self,
        index_name,
    ):
        return index_name in self.indices

    def create_index(
        self,
        index_name,
        mapping,
    ):
        self.indices.add(index_name)
        self.created.append(
            (
                index_name,
                mapping,
            )
        )

    def get_alias(
        self,
        alias_name,
    ):
        result = {}

        for index_name, aliases in (
            self.aliases.items()
        ):
            if alias_name in aliases:
                result[index_name] = {
                    "aliases": {
                        alias_name: dict(
                            aliases[
                                alias_name
                            ]
                        )
                    }
                }

        return result

    def update_aliases(
        self,
        actions,
    ):
        self.actions.extend(actions)

        for action in actions:
            add = action.get("add")

            if not add:
                continue

            index_name = add["index"]
            alias_name = add["alias"]

            self.aliases.setdefault(
                index_name,
                {},
            )[alias_name] = {
                key: value
                for key, value
                in add.items()
                if key not in {
                    "index",
                    "alias",
                }
            }

    def count(
        self,
        target,
    ):
        return 7


class OpenSearchIndexManagerTests(
    unittest.TestCase
):

    def setUp(self):
        self.names = build_index_names(
            "healthcare-lab",
            "healthcare-risk-events",
        )

        self.client = FakeClient()

        self.manager = (
            OpenSearchIndexManager(
                client=self.client,
                names=self.names,
                mapping={
                    "mappings": {
                        "dynamic": False,
                    }
                },
            )
        )

    def test_environment_index_names(self):
        self.assertEqual(
            self.names.read_alias,
            (
                "healthcare-risk-events-"
                "healthcare-lab"
            ),
        )

        self.assertEqual(
            self.names.write_alias,
            (
                "healthcare-risk-events-"
                "healthcare-lab-write"
            ),
        )

        self.assertEqual(
            self.names.first_backing_index,
            (
                "healthcare-risk-events-"
                "healthcare-lab-000001"
            ),
        )

    def test_ensure_creates_index_and_aliases(self):
        result = self.manager.ensure()

        self.assertTrue(
            result["created_index"]
        )

        self.assertIn(
            self.names.first_backing_index,
            self.client.indices,
        )

        read_response = (
            self.client.get_alias(
                self.names.read_alias
            )
        )

        write_response = (
            self.client.get_alias(
                self.names.write_alias
            )
        )

        self.assertIn(
            self.names.first_backing_index,
            read_response,
        )

        self.assertTrue(
            write_response[
                self.names
                .first_backing_index
            ]["aliases"][
                self.names.write_alias
            ]["is_write_index"]
        )

    def test_ensure_is_idempotent(self):
        first = self.manager.ensure()
        second = self.manager.ensure()

        self.assertTrue(
            first["created_index"]
        )

        self.assertFalse(
            second["created_index"]
        )

        self.assertEqual(
            len(self.client.created),
            1,
        )

    def test_status_reports_healthy_aliases(self):
        self.manager.ensure()

        status = self.manager.status()

        self.assertTrue(
            status["healthy"]
        )

        self.assertEqual(
            status["document_count"],
            7,
        )

        self.assertEqual(
            status["write_indices"],
            [
                self.names
                .first_backing_index
            ],
        )


if __name__ == "__main__":
    unittest.main()