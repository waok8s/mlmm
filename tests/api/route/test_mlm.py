import os
from unittest import mock

import requests

from mlmm import app


class TestMlm:
    """
    mlmm.api.route.mlmm.py のテスト
    """

    def setup_class(self):
        self.client = app.create_app().test_client()
        self.headers = {"Authorization": "Basic Zm9vOmJhcg=="}

    @staticmethod
    def _mock_redfish(mocker):
        redfish_mock = mocker.Mock()
        mocker.patch("requests.get").return_value = redfish_mock

    def test_get_mlm_default_path(self, mocker):
        """デフォルトのパスからデータファイルを読み込む正常系テスト
        """
        self._mock_redfish(mocker)

        computer_system_id = "437XR1138R2"
        expected = {
            "@odata.type": "#MachineLearningModel.v1_0_0.MachineLearningModel",
            "Name": "Machine Learning Model",
            "@odata.context":
                "/redfish/v1/$metadata#Systems/{}/MachineLearningModel".format(
                    computer_system_id),
            "@odata.id": "/redfish/v1/Systems/{}/MachineLearningModel".format(
                computer_system_id)
        }

        resp = self.client.get(
            "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")

        assert resp.status_code == 200
        assert resp.get_json() == expected

    def test_get_mlm_env_path(self, mocker):
        """環境変数で指定したパスからデータファイルを読み込む正常系テスト
        """
        self._mock_redfish(mocker)

        computer_system_id = "437XR1138R2"
        expected = {
            "@odata.type": "#MachineLearningModel.v1_0_0.MachineLearningModel",
            "Name": "Machine Learning Model",
            "@odata.context":
                "/redfish/v1/$metadata#Systems/{}/MachineLearningModel".format(
                    computer_system_id),
            "@odata.id": "/redfish/v1/Systems/{}/MachineLearningModel".format(
                computer_system_id),
            "PowerConsumptionModel": {
                "Name": "PC-PowerEdgeR650xs-2CPU",
                "Url": "http://10.0.0.20",
                "Type": "V2InferenceProtocol",
                "Version": "v0.1.0"},
            "ResponseTimeModel": {
                "Name": "RT-PowerEdgeR650xs-2CPU",
                "Url": "http://10.0.0.20",
                "Type": "V2InferenceProtocol",
                "Version": "v0.1.0"},
        }

        # tests/data/mlm.json
        current_dir_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir_path, os.pardir, os.pardir,
                                 "data", "mlm.json")
        mock_env = {
            "MLM_DATA_FILE_PATH": file_path
        }

        with mock.patch.dict(os.environ, mock_env):
            resp = self.client.get(
                "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")
        actual = resp.get_json()

        assert resp.status_code == 200
        assert actual == expected

    def test_get_mlm_file_not_found_err(self, mocker):
        """指定されたパスのファイルが存在しない異常系テスト
        """
        self._mock_redfish(mocker)

        # tests/data/file_not_found.json（存在しないパス）
        current_dir_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir_path, os.pardir, os.pardir,
                                 "data", "file_not_found.json")
        mock_env = {
            "MLM_DATA_FILE_PATH": file_path
        }

        with mock.patch.dict(os.environ, mock_env):
            resp = self.client.get(
                "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")

        expected_json = {
            "error": {
                "code": "",
                "message": "See @Message.ExtendedInfo for more information",
                "@Message.ExtendedInfo": [
                    {
                        "Message": "Internal error occurred."
                    }
                ]
            }
        }

        assert resp.status_code == 500
        assert resp.json == expected_json

    def test_get_mlm_not_json_err(self, mocker):
        """読み込んだデータがJSON形式でない異常系テスト
        """
        self._mock_redfish(mocker)

        # tests/data/not_json.json
        current_dir_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir_path, os.pardir, os.pardir,
                                 "data", "not_json.json")
        mock_env = {
            "MLM_DATA_FILE_PATH": file_path
        }

        with mock.patch.dict(os.environ, mock_env):
            resp = self.client.get(
                "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")

        expected_json = {
            "error": {
                "code": "",
                "message": "See @Message.ExtendedInfo for more information",
                "@Message.ExtendedInfo": [
                    {
                        "Message": "Internal error occurred."
                    }
                ]
            }
        }

        assert resp.status_code == 500
        assert resp.json == expected_json

    def test_get_mlm_redfish_http_error(self, mocker):
        """Redfish APIでHTTPエラーが返却された場合の異常系テスト
        """
        redfish_mock = mocker.Mock()
        dummy_resp = requests.Response()
        dummy_resp._content = b'{"ham": "eggs"}'
        dummy_resp.status_code = 400
        mock_exception = requests.exceptions.HTTPError(response=dummy_resp)
        redfish_mock.raise_for_status.side_effect = mock_exception
        mocker.patch("requests.get").return_value = redfish_mock

        expected_json = {
            "ham": "eggs"
        }

        resp = self.client.get(
            "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")

        assert resp.status_code == 400
        assert resp.json == expected_json

    def test_get_mlm_redfish_request_error(self, mocker):
        """Redfish APIのリクエストで接続エラー等が発生した場合の異常系テスト
        """
        mocker.patch("requests.get").side_effect = requests.ConnectionError()

        expected_json = {
            "error": {
                "code": "",
                "message": "See @Message.ExtendedInfo for more information",
                "@Message.ExtendedInfo": [
                    {
                        "Message": "Internal error occurred."
                    }
                ]
            }
        }

        resp = self.client.get(
            "/redfish/v1/Systems/437XR1138R2/MachineLearningModel")

        assert resp.status_code == 500
        assert resp.json == expected_json
