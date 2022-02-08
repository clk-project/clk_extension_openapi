#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
from json.decoder import JSONDecodeError
from pathlib import Path
from textwrap import indent

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

LOGGER = get_logger(__name__)


class OpenApi:

    @property
    def verify(self):
        return not self.no_verify

    @property
    def bearer(self):
        if not self._bearer:

            @cache_disk(expire=3600)
            def update_bearer():
                return check_output(
                    ["clk", "openapi", "--bearer", "None", "get-token"],
                    internal=True,
                ).strip()

            self._bearer = update_bearer()
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
@option(
    "--bearer",
    help=("Security token to access the API."
          " Will use the result of the command openapi.get-token by default"),
)
def openapi(base_url, api_url, no_verify, bearer):
    "Manipulate openapi"
    config.openapi._bearer = bearer

    if config.openapi.no_verify:
        # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        # We assume the user know what per is doing because per explicitly asked
        # not to verify
        import urllib3
        urllib3.disable_warnings()


@cache_disk(expire=3600)
def api():
    result = requests.get(
        config.openapi.api_url,
        verify=config.openapi.verify,
    ).json()
    return result


def get(path, headers, json=None, query_parameters=None):
    "Get the api"
    json = json or {}
    query_parameters = query_parameters or {}
    if "security" in api()["paths"][path]["get"]:
        if config.openapi.bearer:
            headers["Authorization"] = "Bearer " + config.openapi.bearer
    formatted_path = path.format(**json)
    if query_parameters:
        formatted_path += "?"
    for key, value in query_parameters.items():
        formatted_path += f"{key}={value}"

    LOGGER.action(f"Getting {formatted_path}")
    resp = requests.get(
        config.openapi.base_url + formatted_path,
        verify=config.openapi.verify,
        headers=headers,
    )
    try:
        return resp.json()
    except JSONDecodeError:
        raise click.UsageError("Cannot interpret the following as json in the"
                               f" post answer: {resp.text}")


@openapi.command()
def get_token():
    """Command to get a valid token"""


class GetRessource(DynamicChoice):
    def choices(self):
        def openapi_get_keys():
            paths = api()["paths"]
            return [key for key, values in paths.items() if "get" in values]

        return openapi_get_keys()


def get_get_parameters(path):
    api_ = api()
    path_data = api_["paths"][path]["get"]
    parameters = path_data.get("parameters", [])
    for parameter in parameters:
        schema = parameter["schema"]
        if "$ref" in schema:
            ref = schema["$ref"]
            parameter["schema"] = dict_json_path(api_, ref)
    return parameters


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


class GetParameters(Header):
    def choices(self):
        keys = super().choices()
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()

        parameters = get_get_parameters(config.openapi_current.path)

        def separator(parameter):
            if parameter.get("in") == "query":
                return "?"
            else:
                return "="

        return [
            parameter["name"] + separator(parameter)
            for parameter in parameters
            if not parameter["name"] in config.openapi_current.given_value
        ] + keys

    def convert(self, value, param, ctx):
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        config.openapi_current.given_value.add(value.split("=")[0])
        return value


def get_callback(ctx, attr, value):
    config.openapi_current.method = "get"
    return value


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
    type=GetParameters(),
    nargs=-1,
)
def _get(path, arguments):
    """Get the given path"""
    headers = {
        header.split(":")[0]: header.split(":")[1]
        for header in arguments if ":" in header
    }
    json = {
        parameter.split("=")[0]: parameter.split("=")[1]
        for parameter in arguments if "=" in parameter
    }
    query_parameters = {
        parameter.split("?")[0]: parameter.split("?")[1]
        for parameter in arguments if "?" in parameter
    }
    echo_json(get(path, headers, json=json, query_parameters=query_parameters))


def post(path, json, headers=None):
    "post the api"
    headers = headers or {}
    if "security" in api()["paths"][path]["post"]:
        if config.openapi.bearer:
            headers["Authorization"] = "Bearer " + config.openapi.bearer
    formatted_path = path.format(**json)
    json = {
        key: value
        for key, value in json.items() if key in get_post_properties(path)
    }
    LOGGER.action(f"Posting to {formatted_path}")

    resp = requests.post(
        config.openapi.base_url + path,
        verify=config.openapi.verify,
        json=json,
        headers=headers,
    )
    try:
        return resp.json()
    except JSONDecodeError:
        raise click.UsageError("Cannot interpret the following as json in the"
                               f" post answer: {resp.text}")


class PostRessource(DynamicChoice):
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


def get_post_properties(path):
    api_ = api()
    path_data = api_["paths"][path][config.openapi_current.method]
    if "requestBody" not in path_data:
        return {}
    schema = path_data["requestBody"]["content"]["application/json"]["schema"]
    if "$ref" in schema:
        ref = schema["$ref"]
        schema = dict_json_path(api_, ref)
    return schema["properties"]


def get_post_parameters(path):
    api_ = api()
    path_data = api_["paths"][path][config.openapi_current.method]
    parameters = path_data.get("parameters", [])
    for parameter in parameters:
        schema = parameter["schema"]
        if "$ref" in schema:
            ref = schema["$ref"]
            parameter["schema"] = dict_json_path(api_, ref)
    return parameters


class PostPropertiesRessource(Header):
    def choices(self):
        keys = super().choices()
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        properties = get_post_properties(config.openapi_current.path)
        parameters = get_post_parameters(config.openapi_current.path)
        return [
            parameter["name"] + "=" for parameter in parameters
            if not parameter["name"] in config.openapi_current.given_value
        ] + [
            key + "=" for key in properties.keys()
            if not key in config.openapi_current.given_value
        ] + keys

    def convert(self, value, param, ctx):
        if not hasattr(config.openapi_current, "given_value"):
            config.openapi_current.given_value = set()
        config.openapi_current.given_value.add(value.split("=")[0])
        res = {}
        if value.startswith("@"):
            filepath = value[len("@"):]
            values = json.loads(Path(filepath).read_text())
            res["value"] = values
            res["type"] = "value"
        elif "=@" in value:
            key, value = value.split("=")
            filepath = value[len("@"):]
            value = json.loads(Path(filepath).read_text())
            res["type"] = "value"
            res["value"] = {key: value}
            return key, value
        elif "=" in value:
            key, value = value.split("=")
            value = parse_value(value)
            res["type"] = "value"
            res["value"] = {key: value}
        elif ":" in value:
            key, value = value.split(":")
            res["type"] = "header"
            res["value"] = {key: value}
        else:
            raise NotImplementedError()
        return res


def parse_value(value):
    if value.startswith("[") or value.startswith("{") or value.startswith('"'):
        return json.loads(value)
    else:
        return value


def parse_value_properties(value, type_):
    if type_ == "number":
        return int(value)
    else:
        return value


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
    type=PostRessource("post"),
    callback=post_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=PostPropertiesRessource(),
              expose_value=True)
def _post(path, params):
    """post to the given path"""
    headers = {}
    for param in params:
        if param["type"] == "header":
            headers.update(param["value"])
    values = {}
    for param in params:
        if param["type"] == "value":
            values.update(param["value"])
    echo_json(post(path, headers=headers, json=values))


def patch(path, json, headers=None):
    "patch to the api"
    headers = headers or {}
    if "security" in api()["paths"][path][config.openapi_current.method]:
        if config.openapi.bearer:
            headers["Authorization"] = "Bearer " + config.openapi.bearer
    formatted_path = path.format(**json)
    json = {
        key: parse_value_properties(
            value,
            get_post_properties(path).get(key, {}).get("type"))
        for key, value in json.items() if key in get_post_properties(path)
    }
    LOGGER.action(f"Patching to {formatted_path}")

    resp = requests.patch(
        config.openapi.base_url + path,
        verify=config.openapi.verify,
        json=json,
        headers=headers,
    )
    try:
        return resp.json()
    except JSONDecodeError:
        raise click.UsageError("Cannot interpret the following as json in the"
                               f" post answer: {resp.text}")


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
    type=PostRessource("patch"),
    callback=patch_callback,
)
@param_config("openapi_current",
              "params",
              kls=argument,
              nargs=-1,
              help="The arguments, separated by =",
              type=PostPropertiesRessource(),
              expose_value=True)
def _patch(path, params):
    """post to the given path"""
    headers = {}
    for param in params:
        if param["type"] == "header":
            headers.update(param["value"])
    values = {}
    for param in params:
        if param["type"] == "value":
            values.update(param["value"])
    echo_json(patch(path, headers=headers, json=values))


@openapi.command()
@param_config(
    "openapi_current",
    "path",
    kls=argument,
    expose_value=True,
    help="The path to post to",
    type=PostRessource("post"),
)
def describe_post(path):
    """Show the expected properties of the given path."""
    config.openapi_current.method = "post"
    properties = get_post_properties(path)
    parameters = get_post_parameters(path)

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
        print(dump_desc(parameter["schema"]))

    for property, desc in properties.items():
        print(f"{property}:")
        print(dump_desc(desc))


@openapi.command()
def ipython():
    r = requests.get(
        config.openapi.api_url,
        verify=config.openapi.verify,
    ).json()
    import IPython
    dict_ = globals()
    dict_.update(locals())
    IPython.start_ipython(argv=[], user_ns=dict_)
