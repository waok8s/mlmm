from mlmm.utils import common_utils


class TestCommonUtils:
    def test_capitalize_key_single_string_key(self):
        dictionary = {"Abc": "def", "ghi": "jkl", "m": "n"}
        expected = {"Abc": "def", "Ghi": "jkl", "M": "n"}
        actual = common_utils.capitalize_key(dictionary)
        assert actual == expected

    def test_capitalize_key_hierarchical_dict(self):
        dictionary = {
            "ham": {
                "eggs": {
                    "x": "good"
                },
                "spam": {}
            }
        }
        expected = {
            "Ham": {
                "Eggs": {
                    "X": "good"
                },
                "Spam": {}
            }
        }
        actual = common_utils.capitalize_key(dictionary)
        assert actual == expected

    def test_capitalize_key_contain_list(self):
        dictionary = {
            "ham": ["a", "b", "c"],
            "eggs": [
                {
                    "a": "b",
                    "x": "y",
                },
                {
                    "c": "d",
                    "z": "v"
                }
            ],
            "spam": [
                [
                    {"hoge": "foo"}
                ]
            ]
        }
        expected = {
            "Ham": ["a", "b", "c"],
            "Eggs": [
                {
                    "A": "b",
                    "X": "y",
                },
                {
                    "C": "d",
                    "Z": "v"
                }
            ],
            "Spam": [
                [
                    {"Hoge": "foo"}
                ]
            ]
        }
        actual = common_utils.capitalize_key(dictionary)
        assert actual == expected
