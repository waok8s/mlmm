# Machine Learning Model Management API

## Build image

In this directory run:

```bash
$ docker build -t nedopj/mlmm:2.1 .
```

## Settings

### Environment variables

This API uses environment variables for configuration.

| Environment variables| description | required | default value |
| -------------------- | ----------- | -------- | ------------- |
| REDFISH_SCHEME | Redfish url scheme | false | https |
| REDFISH_HOST | Redfish host to access | true |- |
| REDFISH_PORT | Redfish port to access | false |443 |
| MLM_DATA_FILE_PATH | File path of machine learning model data returned by this API | false | \<PROJECT ROOT\>/data/mlm.json  |

### Machine learning model data file

Set the data returned by this API in json format as follows.  
This file is stored in the path set by the environment variables `MLM_DATA_FILE_PATH`.

```json
{
  "powerConsumptionModel": {
    "name": "PC-PowerEdgeR650xs-2CPU",
    "url": "http://10.0.0.20",
    "type": "V2InferenceProtocol",
    "version": "v0.1.0"
  },
  "responseTimeModel": {
    "name": "RT-PowerEdgeR650xs-2CPU",
    "url": "http://10.0.0.20",
    "type": "V2InferenceProtocol",
    "version": "v0.1.0"
  }
}
```