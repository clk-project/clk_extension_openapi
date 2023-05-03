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


@group()
@option(
    "--api-url",
    expose_class=OpenApi,
    help="The url of the openapi site",
    expose_value=True,
)
@option(
    "--base-url",
    help="The url of the base of the site",
    expose_value=True,
    expose_class=OpenApi,
)
@flag(
    "--no-verify/--verify",
    expose_class=OpenApi,
    help="Verify https",
    expose_value=True,
)
@flag(
    "--resp-as-text/--resp-as-json",
    expose_class=OpenApi,
    help="Don't try to interpret the resp as json",
)
@option(
    "-o",
    "--output",
    type=Path,
    expose_class=OpenApi,
    help="Some output file to put the result into",
)
@option(
    "--bearer",
    help="Security token to access the API.",
)
@option(
    "-a",
    "--extra-argument",
    help="Extra argument used in all the calls.",
    multiple=True,
)
def openapi(
    base_url,
    api_url,
    no_verify,
    bearer,
    extra_argument,
):
    """Play with some API defined with openapi v3

    Simply provide the --base-url to the root of the API and --api-url to the definition,
    in json of the API.

    Then, use one of the 5 classical verbs get, put, post, patch and delete and then
    let TAB TAB guide your steps.

    You will notice that there are 4 kinds of arguments: path, query, headers
    and body (in json). Those are given of the form <key><separator><value>,
    where separator is respectively ?, &, : and =.

    Thus posting to the endpoint /a with a body of {"a": "b"} and header of c=d
    would look like this:

    clk openapi post /a a=b c:d

    The values are checked using JSON schema before sending them to the server.

    You can provide a bearer token that while be given in the Authorization
    header and prefixed with Bearer.

    You can also provide default global values with --extra-arguments. Those
    will be parsed, JSON schema validated and added as default values of the
    arguments only if the schema of the given path accept such argument name and
    type. For example --extra-argument a=b would provide the default body {"a":
    "b"} only to the endpoints that accept a body parameter named a.

    """
    config.openapi.bearer = bearer
    config.openapi.extra_arguments = extra_argument

    if config.openapi.no_verify:
        # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        # We assume the user know what per is doing because per explicitly asked
        # not to verify
        import urllib3
        urllib3.disable_warnings()


class APIUnavailable(Exception):
    pass


class APIVersionMismatch(Exception):
    pass


def api():

    @cache_disk(expire=3600)
    def _api(url):
        resp = requests.get(
            url,
            verify=config.openapi.verify,
        )
        if resp.status_code // 100 != 2:
            raise APIUnavailable()
        if url.endswith(".yml") or url.endswith(".yaml"):
            import yaml
            result = yaml.safe_load(resp.text)
        else:
            result = resp.json()
        if version := result.get("openapi"):
            if not version.startswith("3"):
                LOGGER.warn(f"You are using openapi v{version} (!= 3)."
                            " Not sure it will work.")
        elif version := result.get("swagger"):
            if version.startswith("2"):
                LOGGER.warn(f"You are using swagger v{version}."
                            " It does not work well.")
            else:
                LOGGER.warn(f"You are using swagger v{version}."
                            " Not sure it will work.")

        return result

    return _api(config.openapi.api_url)


@openapi.command()
@table_format(default='key_value')
@table_fields(choices=['description', 'url'])
def list_servers_urls(format, fields):
    """Show the servers that you might want to provide as base"""
    with TablePrinter(fields, format) as tp:
        tp.echo_records([{
            **{
                'description': 'NA'
            },
            **server
        } for server in api()["servers"]])


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
        for argument in config.openapi.extra_arguments:
            value = Payload.convert_value(
                argument,
                config.openapi_current.path,
                config.openapi_current.method,
                silent_fail=True,
            )
            if value:
                type_to_dict[value["type"]].update(value["value"])
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
        if config.openapi.bearer:
            # follow the OAuth 2.0 standard, see https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
            headers["Authorization"] = "Bearer " + config.openapi.bearer

    def handle_resp(self, resp):
        if resp.status_code // 100 != 2:
            LOGGER.info(f"Code: {resp.status_code}")
        else:
            LOGGER.debug(f"Code: {resp.status_code}")
        if config.openapi.resp_as_text:
            result = resp.text
        else:
            try:
                result = resp.json()
            except (JSONDecodeError, SimplejsonJSONDecodeError):
                raise click.UsageError(
                    "Cannot interpret the following as json in the"
                    f" post answer: '{resp.text}'")
        self.echo_result(result)
        if resp.status_code // 100 != 2:
            return 1

    def echo_result(self, result):
        if config.openapi.output is not None:
            config.openapi.output.write_text(result)
        else:
            if config.openapi.resp_as_text:
                print(result)
            else:
                echo_json(result)


class GetRessource(DynamicChoice):

    def choices(self):

        def openapi_get_keys():
            paths = api()["paths"]
            return [key for key, values in paths.items() if "get" in values]

        return openapi_get_keys()


def get_callback(ctx, attr, value):
    config.openapi_current.method = "get"
    return value


class Payload(DynamicChoice):

    parameter_to_separator = {
        "query": "&",
        "body": "=",
        "path": "?",
        "header": ":",
    }
    separator_to_parameter = {
        value: key
        for key, value in parameter_to_separator.items()
    }

    def choices(self):
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        parameters = get_openapi_parameters(config.openapi_current.path,
                                            config.openapi_current.method)

        return [
            parameter["name"] + self.parameter_to_separator[parameter["in"]]
            for parameter in parameters
            if not parameter["name"] in config.openapi_current.given_value
        ]

    def convert(self, value, param, ctx):
        return self.convert_value(
            value,
            config.openapi_current.path,
            config.openapi_current.method,
        )

    @classmethod
    def convert_value(clk, value, path, method, silent_fail=False):
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
        parameters = get_openapi_parameters(path, method)
        for param in parameters:
            if param["name"] == key:
                value = parse_value_properties(value, param["schema"])
                break
        else:
            if silent_fail:
                return {}
            else:
                raise NotImplementedError()
        res["value"] = {key: value}
        res["in"] = res["type"]
        res["name"] = key
        res["value_raw"] = value
        return res


class OpenAPI_Current:

    def __init__(self):
        pass


@openapi.command()
@argument(
    "path",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="The path to get",
    type=GetRessource(),
    callback=get_callback,
)
@argument(
    "arguments",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="Some header argument",
    type=Payload(),
    nargs=-1,
)
def _get(path, arguments):
    """Get the given path"""
    exit(HTTPAction()(path, arguments))


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


def get_openapi_body_schema(path, method):
    api_ = api()
    path_data = api_["paths"][path][method]
    if "requestBody" not in path_data:
        return {}
    schema = path_data["requestBody"]["content"]["application/json"]["schema"]
    if "$ref" in schema:
        ref = schema["$ref"]
        schema = dict_json_path(api_, ref)
    return schema


def get_security_schemes():
    return api()["components"].get("securitySchemes", {})


def get_security_params(path, method):
    api_ = api()
    path_data = api_["paths"][path][method]
    schemes = get_security_schemes()
    for security in path_data.get("security", []):
        for key in security.keys():
            scheme = schemes[key]
            if scheme["type"] == "apiKey":
                scheme = scheme.copy()
                scheme["schema"] = {"type": "string"}
                yield scheme


def get_openapi_parameters(path, method):
    api_ = api()
    path_data = api_["paths"][path][method]
    parameters = path_data.get("parameters", [])
    # get the body in a normal parameter
    if schema := get_openapi_body_schema(path, method):
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
    parameters2.extend(get_security_params(path, method))
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
@argument(
    "path",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="The path to delete to",
    type=OpenApiResource("delete"),
    callback=delete_callback,
)
@argument("params",
          expose_class=OpenAPI_Current,
          nargs=-1,
          help="The arguments, separated by =",
          type=Payload(),
          expose_value=True)
def _delete(path, params):
    """delete to the given path"""
    exit(HTTPAction()(path, params))


def post_callback(ctx, attr, value):
    config.openapi_current.method = "post"
    return value


@openapi.command()
@argument(
    "path",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="The path to post to",
    type=OpenApiResource("post"),
    callback=post_callback,
)
@argument("params",
          expose_class=OpenAPI_Current,
          nargs=-1,
          help="The arguments, separated by =",
          type=Payload(),
          expose_value=True)
def _post(path, params):
    """post to the given path"""
    exit(HTTPAction()(path, params))


def patch_callback(ctx, attr, value):
    config.openapi_current.method = "patch"
    return value


@openapi.command()
@argument(
    "path",
    expose_value=True,
    help="The path to patch to",
    type=OpenApiResource("patch"),
    callback=patch_callback,
)
@argument("params",
          expose_class=OpenAPI_Current,
          nargs=-1,
          help="The arguments, separated by =",
          type=Payload(),
          expose_value=True)
def _patch(path, params):
    """post to the given path"""
    exit(HTTPAction()(path, arguments))


def put_callback(ctx, attr, value):
    config.openapi_current.method = "put"
    return value


@openapi.command()
@argument(
    "path",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="The path to put to",
    type=OpenApiResource("put"),
    callback=put_callback,
)
@argument("params",
          expose_class=OpenAPI_Current,
          nargs=-1,
          help="The arguments, separated by =",
          type=Payload(),
          expose_value=True)
def _put(path, params):
    """put to the given path"""
    exit(HTTPAction()(path, params))


@openapi.command()
@argument(
    "path",
    expose_class=OpenAPI_Current,
    expose_value=True,
    help="The path to describe",
    type=OpenApiResource("post"),
)
def describe_post(path):
    """Show the expected properties of the given path."""
    describe_api("post", path)


@openapi.command()
@argument(
    "path",
    expose_class=OpenAPI_Current,
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
