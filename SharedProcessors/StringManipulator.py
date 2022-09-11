#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2022 Ian Cohn
# https://www.github.com/iancohn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from inspect import _void

from autopkglib import Processor, ProcessorError, URLTextSearcher

ACTION_TYPE_OPTIONS = [
    "replace",
    "split",  # Returns an array to the output variable
    # "loop",
    "concatenate",
    "match",
]

"""
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.com/tree",
    "$dynamicAnchor": "node",
    "type": "array",
    "prefixItems": [
        {"$ref": "#/$defs/action"}
    ],
    "properties":{
        
    },
    "$defs": {
        "action": {
            "type": "object",
            "properties": {
                "action_type": {
                    "$ref": "#/action_type"
                },
                "action_input_var": {
                    "type": "string"
                },
                "action_output_var": {
                    "type": "string"
                },
                "options": {
                    "oneOf":[
                        {
                            "$ref": "#/replace_options"
                        },
                        {
                            "$ref": "#/split_options"
                        }
                    ]
                }
            },
            "required":[
                "action_type",
                "options"
            ],
            "additionalProperties": False
        },
        "replace_options": 1,
        "action_type": {
            "enum": [
                "replace",
                "split",
                "loop",
                "concatenate",
                "match",
                "retrieve_url",
                "format"
            ],
            "type": "string"
        },
        "options": {
            "type": "object"
        }
    }
}


OBJECT_SCHEMA_DESCRIPTIONS = {
    "action": {
        "action_type": "replace",#enum
        "action_input_var": "var",#string
        "action_output_var": "var",#string
        "options": {
            #options object schema depends on action_type enum value
        }
    },
    "replace_arguments": {
        "replacements": [
            {
                "find_text": "a string to find",
                "replace_text": "replace it with this.",
                "replace_all": True
            },
            {
                "find_text": "a string to find",
                "replace_text": "replace it with this.",
                "replace_all": True
            }
        ]
    }

}
"""

REPLACE_ACTION_SAMPLE = {
    "input_variable_name": "output",
    "action_type": "replace",
    "output_variable_name": "output",
    "options": {
        "replacements": [
            {
                "find_text": "a string to find",
                "replace_text": "replace it with this.",
                "replace_n": -1,
            },
            {
                "find_text": "another string to find",
                "replace_text": "replace it with something else.",
                "replace_n": 1,
            },
        ]
    },
}
MATCH_ACTION_SAMPLE = {
    "action_input_var": "input/item",
    "action_type": "match",
    "action_output_var": "output",
    "arguments": {"re_pattern": "", "re_flags": [], "find_all": True},
}
SPLIT_ACTION_SAMPLE = {
    "action_input_var": "input",
    "action_type": "split",
    "action_output_var": "output",
    "arguments": {
        "split_on_text": ",",
    },
}
LOOP_ACTION_SAMPLE = {
    "action_input_var": "input",
    "action_type": "loop",
    "action_output_var": "output",
    "arguments": {},
}
CONCATENATE_ACTION_SAMPLE = {
    "action_input_var_var": "",
    "action_type": "concatenate",
    "action_output_var": "output",
    "arguments": {"concatenate_with_text": ""},
}

__all__ = ["StringManipulator"]


class StringManipulator(URLTextSearcher):
    """Parse, manipulate, and return a string."""

    description = __doc__

    input_variables = {
        "manipulation_actions": {
            "required": True,
            "description": (
                "An array of dictionaries representing the actions to take."
            ),
        }
    }
    output_variables = {}

    def replace_text(
        self,
        input_variable_name: str = "output",
        output_variable_name: str = "output",
        options: dict = {"replacements": []},
    ) -> _void:
        self.output(
            "Getting input variable with name: {}".format(input_variable_name),
            verbose_level=3,
        )
        myString = self.env.get(input_variable_name)
        replacements = options["replacements"]
        if len(replacements) == 0:
            raise (ProcessorError("No replacements indicated."))
        else:
            self.output(
                "{} replacements indicated".format(len(replacements)), verbose_level=3
            )

        for replacement in replacements:
            nStrings = replacement["replace_n"] or -1
            searchString = replacement["find_text"]
            replaceString = replacement["replace_text"]
            self.output(
                "FINDING: {}\tREPLACE WITH: {}".format(searchString, replaceString),
                verbose_level=3,
            )
            self.output("IN String: {}".format(myString), verbose_level=3)
            myString = myString.replace(searchString, replaceString, nStrings)
            self.output("OUT String: {}".format(myString), verbose_level=3)
            del nStrings, searchString, replaceString

        self.env[output_variable_name] = myString

    def simple_match_string(
        self,
        input_variable_name: str = "output",
        output_variable_name: str = "output",
        options: dict = {"re_pattern": None, "re_flags": [], "find_all": True},
    ) -> _void:
        """Perform a simple RegEx match (no capture groups) on the string. Sets the output_variable_name to an array of matches"""

        self.output(
            "Getting input variable with name: {}".format(input_variable_name),
            verbose_level=3,
        )
        myString = self.env.get(input_variable_name)

        self.output("Preparing RegEx Flags", verbose_level=3)
        self.env["re_flags"] = options["re_flags"] or []
        flags = self.prepare_re_flags()

        self.output("Creating RegEx matching object.", verbose_level=3)
        rePattern = re.compile(options["re_pattern"], flags=flags)

        self.output("Finding match.", verbose_level=3)
        if options["find_all"] == True:
            self.env[output_variable_name] = rePattern.findall(myString)
        else:
            self.env[output_variable_name] = rePattern.search(myString).group()

        if rePattern.search(myString):
            self.output("Found match.", verbose_level=3)
        else:
            self.output("No matches found.", verbose_level=3)

    def split_string(
        self,
        input_variable_name: str = "output",
        output_variable_name: str = "output",
        options: dict = {"split_on_text": None},
    ) -> _void:
        split = options["split_on_text"] or ","
        self.output("Splitting text on sequence: '{}'".format(split), verbose_level=3)
        self.env[output_variable_name] = self.env[input_variable_name].split(split)

        self.output(
            "{} strings returned.".format(len(self.env[output_variable_name])),
            verbose_level=3,
        )

    def concatenate_strings(
        self,
        input_variable_name: str = "output",
        output_variable_name: str = "output",
        options: dict = {"concatenate_with_text": ""},
    ) -> _void:
        myArray = self.env[input_variable_name] or []
        self.output(
            "Joining {} string(s) using sequence: '{}'".format(
                len(myArray), options["concatenate_with_text"]
            ),
            verbose_level=3,
        )
        joinText = options["concatenate_with_text"]
        self.env[output_variable_name] = joinText.join(myArray)

    def main(self):
        actionFunctions = {
            "replace": self.replace_text,
            "simple_match": self.simple_match_string,
            "concatenate": self.concatenate_strings,
            "split": self.split_string,
        }

        manipulationActions: list = self.env.get("manipulation_actions")
        if len(manipulationActions) == 0:
            raise (ProcessorError("No actions configured"))

        self.output(
            "Processing {} string manipulations".format(len(manipulationActions)),
            verbose_level=1,
        )
        try:
            for manipulationAction in manipulationActions:
                if "output_variable_name" in manipulationAction:
                    outputVarName = manipulationAction["output_variable_name"]
                else:
                    outputVarName = "output"

                if "input_variable_name" in manipulationAction:
                    inputVarName = manipulationAction["input_variable_name"]
                else:
                    inputVarName = "output"

                self.output(
                    "Performing ({}) on string.".format(
                        manipulationAction["action_type"]
                    ),
                    verbose_level=3,
                )
                self.output("Input Variable: {}".format(inputVarName), verbose_level=3)
                self.output(
                    "Output Variable: {}".format(outputVarName), verbose_level=3
                )

                actionFunctions[manipulationAction["action_type"]](
                    inputVarName, outputVarName, manipulationAction["options"]
                )
                self.output(
                    "{}: {}".format(outputVarName, self.env[outputVarName]),
                    verbose_level=3,
                )

        except Exception as e:
            raise ProcessorError(e)

        self.output("Completed string manipulations.", verbose_level=2)


if __name__ == "__main__":
    PROCESSOR = StringManipulator()
    PROCESSOR.execute_shell()
