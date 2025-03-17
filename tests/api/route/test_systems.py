from mlmm import app


class TestSystems:
    """
    mlmm.api.route.systems.py のテスト
    """

    def setup_class(self):
        self.client = app.create_app().test_client()
        self.headers = {"Authorization": "Basic Zm9vOmJhcg=="}

    def test_get_systems(self, mocker):
        """正常系テスト
        """
        redfish_mock = mocker.Mock()
        redfish_mock.status_code = 200
        # Redfish APIの /redfish/v1/systems/437XR1138R2 のレスポンスの一部のみ再現
        systems_mock_data = {
            "@odata.type": "#ComputerSystem.v1_1_0.ComputerSystem",
            "Id": "437XR1138R2",
            "Name": "WebFrontEnd483"
        }
        redfish_mock.json.return_value = systems_mock_data
        mocker.patch("requests.get").return_value = redfish_mock

        computer_system_id = "437XR1138R2"
        expected = {
            "MachineLearningModel": {
                "@odata.id": "/redfish/v1/Systems/{}/"
                             "MachineLearningModel".format(computer_system_id)
            }
        }
        expected.update(systems_mock_data)

        resp = self.client.get("/redfish/v1/Systems/437XR1138R2",
                               headers=self.headers)

        assert resp.status_code == 200
        assert resp.get_json() == expected
