import logging

from flask import Flask, jsonify, current_app
from werkzeug.exceptions import HTTPException

from mlmm import exceptions as mlmm_exc
from mlmm.api.route import systems
from mlmm.api.route import mlm

REDFISH_URL_PREFIX = "/redfish/v1"


def create_app():
    app = Flask(__name__)
    app.register_blueprint(systems.systems, url_prefix=REDFISH_URL_PREFIX)
    app.register_blueprint(mlm.mlm, url_prefix=REDFISH_URL_PREFIX)

    logger = app.logger
    logger.setLevel(logging.INFO)

    @app.errorhandler(mlmm_exc.RedfishRequestError)
    def handle_redfish_error(e):
        """Error handling for Redfish Request Error.

        Args:
            e (mlmm.exceptions.RedfishRequestError): 例外オブジェクト

        """
        return jsonify(e.message), e.status_code

    @app.errorhandler(HTTPException)
    def handle_exception(e):
        """Common error handling.

        Args:
            e (HTTPException): 例外オブジェクト

        """
        logger.error(e)
        resp = {
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
        return jsonify(resp), e.code

    @app.before_request
    def before_request():
        """A function that outputs a log before a request.
        """
        logger.info('start ' + current_app.name)

    @app.after_request
    def after_request(response):
        """A function that outputs a log after a request.
        """
        logger.info('end ' + current_app.name + ' :: http_status_code=' +
                    str(response.status_code) +
                    ', response=' + str(response.response))
        return response

    return app
