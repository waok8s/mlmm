import json

from flask import abort, current_app


def read_json_file(file_path):
    """Read a JSON file.

    Read the JSON file of the path specified in file_path.

    Args:
        file_path (str): File path to read.

    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, PermissionError, json.JSONDecodeError) as e:
        logger = current_app.logger
        logger.exception(e)
        abort(500, e)
