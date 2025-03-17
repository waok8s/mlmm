import os
from flask import Blueprint, jsonify

from mlmm.utils import redfish_utils, file_utils, common_utils

mlm = Blueprint("mlm", __name__)

current_dir_path = os.path.dirname(os.path.abspath(__file__))


@mlm.route("/Systems/<computer_system_id>/MachineLearningModel",
           methods=["GET"])
def get_mlm(computer_system_id):
    """Return machine learning model data.

    Model data is read from the file in the path set in the environment
    variable MLM_DATA_FILE_PATH.
    If environment variable MLM_DATA_FILE_PATH not set, the model data is
    read from data/mlm.json.
    """

    # 以下を確認するためにredfishにアクセスする：
    # ・認証が成功すること
    # ・computer_system_id のリソースが存在すること
    _ = redfish_utils.request_to_redfish(
        "/Systems/{}".format(computer_system_id))

    fixed_data = {
        "@odata.type": "#MachineLearningModel.v1_0_0.MachineLearningModel",
        "Name": "Machine Learning Model",
        "@odata.context": "/redfish/v1/$metadata#Systems/{}/"
                          "MachineLearningModel".format(computer_system_id),
        "@odata.id": "/redfish/v1/Systems/{}/MachineLearningModel".format(
            computer_system_id)
    }

    default_file_path = os.path.join(current_dir_path, os.pardir, os.pardir,
                                     os.pardir, "data", "mlm.json")
    file_path = os.environ.get("MLM_DATA_FILE_PATH", default_file_path)

    model_data = file_utils.read_json_file(file_path)
    model_data = common_utils.capitalize_key(model_data)
    model_data.update(fixed_data)
    return jsonify(model_data), 200
