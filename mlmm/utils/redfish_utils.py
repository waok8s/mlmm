import os
import requests
from requests import exceptions

from flask import request, abort, current_app

from mlmm import exceptions as mlmm_exc


def request_to_redfish(path):
    """Sends an HTTP GET request to Redfish API with the path specified by
       the argument.

    Args:
        path (str): Specify a path starting with "/" after "/redfish/v1".

    """
    redfish_scheme = os.environ.get("REDFISH_SCHEME", "https")
    redfish_host = os.environ.get("REDFISH_HOST")
    redfish_port = os.environ.get("REDFISH_PORT", "443")

    url = "{}://{}:{}/redfish/v1{}".format(redfish_scheme, redfish_host,
                                           redfish_port, path)

    # 認証情報が含まれるためヘッダーをそのままRedfishに渡す。
    # ただしHostヘッダーにはServiceリソースのホスト名が入ってしまうためRedfishのホスト名に
    # 修正する。
    headers = dict(request.headers)
    headers["Host"] = redfish_host
    # クエリパラメータをそのままRedfishに渡す。
    params = request.args.to_dict()

    try:
        # 内部通信を想定しているため verify=False でSSL証明書の検証を無効にする
        resp = requests.get(url, params=params, headers=headers, verify=False)
        resp.raise_for_status()
        return resp.json()
    except exceptions.HTTPError as e:
        # RedfishへのリクエストでHTTPエラーが発生した場合はエラーの内容をそのまま返却する
        logger = current_app.logger
        logger.error("Request failed. url=(%s)", url)
        logger.error("response=(%s)", e.response.text)
        logger.exception(e)
        raise mlmm_exc.RedfishRequestError(e.response.json(),
                                           e.response.status_code)
    except exceptions.RequestException as e:
        # RedfishへのリクエストでHTTPエラー以外の障害が発生した場合は内部エラーとする
        logger = current_app.logger
        logger.error("Request failed. url=(%s)", url)
        logger.exception(e)
        abort(500)
