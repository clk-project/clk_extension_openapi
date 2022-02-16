#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
from json.decoder import JSONDecodeError
from pathlib import Path
from sys import stdin
from textwrap import indent

from jsonschema import validate, ValidationError
from openapi_schema_to_json_schema import to_json_schema
import click
import requests
from clk.config import config
from clk.core import cache_disk
from clk.decorators import (argument, command, flag, group, option,
                            param_config, table_fields, table_format,
                            use_settings)
from clk.lib import TablePrinter, call, check_output, echo_json
from clk.log import get_logger
from clk.overloads import argument, flag, get_command
from clk.types import DynamicChoice
from simplejson.errors import JSONDecodeError as SimplejsonJSONDecodeError

LOGGER = get_logger(__name__)


def validate_schema(data, schema):
    validate(data, to_json_schema(schema))


def walk_dict(d):
    for key, value in d.items():
        yield key, value
        if isinstance(value, dict):
            yield from walk_dict(value)


class OpenApi:

    @property
    def verify(self):
        return not self.no_verify

    @property
    def bearer(self):
        if not self._bearer:

            @cache_disk(expire=3600)
            def update_bearer(parameters):
                return check_output(
                    ["clk", "openapi", "--bearer", "None", "get-token"],
                    internal=True,
                ).strip()

            self._bearer = update_bearer(
                config.get_parameters("openapi.get-token"))
        return self._bearer


@group()
@param_config(
    "openapi",
    "--api-url",
    typ=OpenApi,
    help="The url of the openapi site",
    expose_value=True,
)
@param_config(
    "openapi",
    "--bearer-token-headers",
    typ=OpenApi,
    help="In what header values we should put the bearer token",
    multiple=True,
    expose_value=True,
)
@param_config(
    "openapi",
    "--base-url",
    typ=OpenApi,
    help="The url of the base of the site",
    expose_value=True,
)
@param_config(
    "openapi",
    "--no-verify/--verify",
    typ=OpenApi,
    kls=flag,
    help="Verify https",
    expose_value=True,
)
@param_config(
    "openapi",
    "--resp-as-text/--resp-as-json",
    typ=OpenApi,
    kls=flag,
    help="Don't try to interpret the resp as json",
)
@param_config(
    "openapi",
    "-o",
    "--output",
    type=Path,
    typ=OpenApi,
    help="Some output file to put the result into",
)
@option(
    "--bearer",
    help=("Security token to access the API."
          " Will use the result of the command openapi.get-token by default"),
)
def openapi(base_url, api_url, no_verify, bearer, bearer_token_headers):
    "Manipulate openapi"
    config.openapi._bearer = bearer

    if config.openapi.no_verify:
        # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        # We assume the user know what per is doing because per explicitly asked
        # not to verify
        import urllib3
        urllib3.disable_warnings()


def api():

    @cache_disk(expire=3600)
    def _api(url):
        result = requests.get(
            url,
            verify=config.openapi.verify,
        ).json()
        return result

    return _api(config.openapi.api_url)


@openapi.command()
@table_format(default='key_value')
@table_fields(choices=['description', 'url'])
def list_servers_urls(format, fields):
    """Show the servers that you might want to provide as base"""
    with TablePrinter(fields, format) as tp:
        tp.echo_records(api()["servers"])


class HTTPAction:

    def __init__(self):
        self.verb = config.openapi_current.method

    def arguments_to_properties(self, arguments):
        headers = {}
        json = {}
        path = {}
        query_parameters = {}
        type_to_dict = {
            "body": json,
            "header": headers,
            "query": query_parameters,
            "path": path
        }
        for _argument in arguments:
            type_to_dict[_argument["type"]].update(_argument["value"])
        if len(json) == 1 and "body" in json:
            json = json["body"]
        return path, headers, json, query_parameters

    def __call__(self, path, params):
        (
            path_parameters,
            headers,
            json,
            query_parameters,
        ) = self.arguments_to_properties(params)
        self.inject_headers(path, headers)
        formatted_path = path.format(**path_parameters)
        if query_parameters:
            formatted_path += "?"
        for key, value in query_parameters.items():
            formatted_path += f"{key}={value}"
        url = config.openapi.base_url + formatted_path
        LOGGER.action(f"{self.verb} {url}")
        if headers:
            LOGGER.debug(f"With headers: {headers}")
        if json:
            LOGGER.debug(f"With json: {json}")
        method = getattr(requests, self.verb)
        resp = method(
            url,
            verify=config.openapi.verify,
            headers=headers,
            json=json,
        )
        return self.handle_resp(resp)

    def inject_headers(self, path, headers):
        security_headers = list(config.openapi.bearer_token_headers)
        for security in api()["paths"][path][self.verb].get("security", []):
            security_headers.extend(security.keys())
        for header in security_headers:
            if header == "Authorization":
                # follow the OAuth 2.0 standard, see https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
                headers[header] = "Bearer " + config.openapi.bearer
            else:
                headers[header] = config.openapi.bearer

    def handle_resp(self, resp):
        if config.openapi.resp_as_text:
            return resp.text
        else:
            try:
                return resp.json()
            except (JSONDecodeError, SimplejsonJSONDecodeError):
                raise click.UsageError(
                    "Cannot interpret the following as json in the"
                    f" post answer: '{resp.text}'")


@openapi.command()
def get_token():
    """Command to get a valid token"""


class GetRessource(DynamicChoice):

    def choices(self):

        def openapi_get_keys():
            paths = api()["paths"]
            return [key for key, values in paths.items() if "get" in values]

        return openapi_get_keys()


class Header(DynamicChoice):

    def choices(self):
        api_ = api()
        parameters = api_["paths"][config.openapi_current.path][
            config.openapi_current.method]
        security = parameters.get("security", {})
        keys = sum([[key + ":" for key in sec.keys()] for sec in security], [])
        return keys

    def convert(self, value, param, ctx):
        return value


def get_callback(ctx, attr, value):
    config.openapi_current.method = "get"
    return value


def echo_result(result):
    if config.openapi.output is not None:
        config.openapi.output.write_text(result)
    else:
        if config.openapi.resp_as_text:
            print(result)
        else:
            echo_json(result)


class Payload(Header):

    parameter_to_separator = {
        "query": "&",
        "body": "=",
        "path": "?",
    }
    separator_to_parameter = {
        value: key
        for key, value in parameter_to_separator.items()
    }

    def choices(self):
        keys = super().choices()
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        parameters = get_openapi_parameters(config.openapi_current.path,
                                            config.openapi_current.method)

        return [
            parameter["name"] + self.parameter_to_separator[parameter["in"]]
            for parameter in parameters
            if not parameter["name"] in config.openapi_current.given_value
        ] + keys

    def convert(self, value, param, ctx):
        return self.convert_value(value, config.openapi_current.path)

    @classmethod
    def convert_value(clk, value, path):
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        config.openapi_current.given_value.add(value.split("=")[0])
        res = {}
        for separator, name in clk.separator_to_parameter.items():
            if separator in value:
                key, value = value.split(separator)
                if value.startswith("@"):
                    filepath = value[len("@"):]
                    if filepath == "-":
                        value = stdin.read()
                    else:
                        value = json.loads(Path(filepath).read_text())
                res["type"] = clk.separator_to_parameter[separator]
                break
        else:
            raise NotImplementedError()
        parameters = get_openapi_parameters(
            path,
            config.openapi_current.method,
        )
        for param in parameters:
            if param["name"] == key:
                value = parse_value_properties(value, param["schema"])
                break
        else:
            raise NotImplementedError()
        res["value"] = {key: value}
        res["in"] = res["type"]
        res["name"] = key
        res["value_raw"] = value
        return res


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to get",
    type=GetRessource(),
    callback=get_callback,
)
@param_config(
    "openapi_current",
    "arguments",
    kls=argument,
    expose_value=True,
    help="Some header argument",
    type=Payload(),
    nargs=-1,
)
def _get(path, arguments):
    """Get the given path"""
    echo_result(HTTPAction()(path, arguments))


class OpenApiResource(DynamicChoice):

    def __init__(self, method, *args, **kwargs):
        super(*args, **kwargs)
        self.method = method

    def choices(self):

        def openapi_post_keys():
            paths = api()["paths"]
            return [
                key for key, values in paths.items() if self.method in values
            ]

        return openapi_post_keys()


def dict_json_path(dict, json_path):
    for elem in json_path.split("/"):
        if elem == "#":
            continue
        dict = dict[elem]
    return dict


def get_openapi_body_schema(path):
    api_ = api()
    path_data = api_["paths"][path][config.openapi_current.method]
    if "requestBody" not in path_data:
        return {}
    schema = path_data["requestBody"]["content"]["application/json"]["schema"]
    if "$ref" in schema:
        ref = schema["$ref"]
        schema = dict_json_path(api_, ref)
    return schema


def get_openapi_parameters(path, method):
    api_ = api()
    path_data = api_["paths"][path][method]
    parameters = path_data.get("parameters", [])
    # get the body in a normal parameter
    if schema := get_openapi_body_schema(path):
        if schema["type"] == "object":
            for name, schema in schema["properties"].items():
                parameters.append({
                    "in": "body",
                    "name": name,
                    "schema": schema,
                })
        else:
            parameters.append({
                "in": "body",
                "name": "body",
                "schema": schema,
                "is_body": True
            })

    parameters2 = []
    for parameter in parameters:
        for key, value in walk_dict(parameter):
            if isinstance(value, dict) and "$ref" in value:
                ref = value["$ref"]
                del value["$ref"]
                value.update(dict_json_path(api_, ref))
        if "schema" not in parameter:
            parameter["schema"] = {"type": parameter["type"]}
        if parameter["in"] == "body" and parameter["schema"][
                "type"] == "object":
            for name, type in parameter["schema"]["properties"].items():
                parameters2.append({
                    "in": "body",
                    "name": name,
                    "schema": type
                })
        else:
            parameters2.append(parameter)

    return parameters2


def parse_value_properties(value, schema):
    try:
        result = json.loads(value)
        validate_schema(result, schema)
        return result
    except (ValidationError, JSONDecodeError) as e:
        if schema["type"] == "string":
            return value
        elif schema["type"] == "boolean":
            if value in ("1", "True", "true"):
                return True
            elif value in ("0", "False", "false"):
                return False
        LOGGER.critical(f"While parsing: {value}, with schema: {schema}")
        raise click.UsageError(e)


def delete_callback(ctx, attr, value):
    config.openapi_current.method = "delete"
    return value


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to delete to",
    type=OpenApiResource("delete"),
    callback=delete_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=Payload(),
              expose_value=True)
def _delete(path, params):
    """delete to the given path"""
    echo_result(HTTPAction()(path, params))


def post_callback(ctx, attr, value):
    config.openapi_current.method = "post"
    return value


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to post to",
    type=OpenApiResource("post"),
    callback=post_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=Payload(),
              expose_value=True)
def _post(path, params):
    """post to the given path"""
    echo_result(HTTPAction()(path, params))


def patch_callback(ctx, attr, value):
    config.openapi_current.method = "patch"
    return value


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to patch to",
    type=OpenApiResource("patch"),
    callback=patch_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=Payload(),
              expose_value=True)
def _patch(path, params):
    """post to the given path"""
    echo_result(HTTPAction()(path, arguments))


def put_callback(ctx, attr, value):
    config.openapi_current.method = "put"
    return value


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to put to",
    type=OpenApiResource("put"),
    callback=put_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=Payload(),
              expose_value=True)
def _put(path, params):
    """put to the given path"""
    echo_result(HTTPAction()(path, params))


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to describe",
    type=OpenApiResource("post"),
)
def describe_post(path):
    """Show the expected properties of the given path."""
    describe_api("post", path)


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to describe",
    type=OpenApiResource("get"),
)
def describe_get(path):
    """Show the expected properties of the given path."""
    describe_api("get", path)


def describe_api(method, path):
    config.openapi_current.method = method
    parameters = get_openapi_parameters(path, method)

    def dump_desc(desc):
        indentation = "  "
        if "$ref" in desc:
            desc = dict_json_path(api(), desc["$ref"])
        if "oneOf" in desc:
            return f"{indentation}{indentation} or \n".join(
                indent(dump_desc(candidate), indentation)
                for candidate in desc["oneOf"])
        res = f'type: {desc["type"]}\n'
        if "description" in desc:
            res += f'desc:\n'
            res += indent(desc["description"], indentation)
            res += '\n'
        elif "items" in desc:
            res += "items:\n"
            res += indent(dump_desc(desc["items"]), indentation)
        elif desc["type"] == "object":
            if "required" in desc:
                res += "required:\n"
                for required in desc["required"]:
                    res += f'{indentation}{required}\n'
            if "properties" in desc:
                res += 'properties:\n'
                for name, values in desc["properties"].items():
                    res += f"{indentation}{name}:\n"
                    res += indent(dump_desc(values), indentation)
        else:
            res += "NA\n"
        return indent(res, indentation)

    for parameter in parameters:
        print(f"{parameter['name']}:")
        print(f"  in: {parameter['in']}")
        print(dump_desc(parameter["schema"]))


@openapi.command()
def ipython():
    """Run an interactive python console to play with the code"""
    r = requests.get(
        config.openapi.api_url,
        verify=config.openapi.verify,
    ).json()
    import IPython
    dict_ = globals()
    dict_.update(locals())
    IPython.start_ipython(argv=[], user_ns=dict_)
