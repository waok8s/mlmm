from flask import Blueprint, jsonify

from mlmm.utils import redfish_utils

systems = Blueprint("systems", __name__)


@systems.route("/Systems/<computer_system_id>", methods=["GET"])
def get_system(computer_system_id):
    """Return system data of redfish with machine learning model resource
       path added.
    """
    additional_data = {
        "MachineLearningModel": {
            "@odata.id": "/redfish/v1/Systems/{}/MachineLearningModel".format(
                computer_system_id)
        }
    }

    # /System/<computer_system_id> へのリクエストが成功することで認証が成功したこととする
    resp_json = redfish_utils.request_to_redfish(
        "/Systems/{}".format(computer_system_id))
    resp_json.update(additional_data)

    return jsonify(resp_json), 200
