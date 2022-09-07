#!/usr/bin/python3
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

from array import array
from dataclasses import replace
from distutils.filelist import findall
from autopkglib import ProcessorError, UrlGetter
import re,json

ACTION_TYPE_OPTIONS = [
	"replace",
	"split", # Returns an array to the output variable
	"loop",
	"concatenate",
	"match"
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
	"action_input_var": "input",
	"action_type": "replace",
	"action_output_var": "output",
	"options": {
		"replacements": [
			{
				"find_text": "a string to find",
				"replace_text": "replace it with this.",
				"replace_n": -1
			},
			{
				"find_text": "another string to find",
				"replace_text": "replace it with something else.",
				"replace_n": 1
			}
		]
	}
}
SPLIT_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "split",
	"action_output_var": "output",
	"arguments": {
		"split_on_text": ",",
	}
}
LOOP_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "loop",
	"action_output_var": "output",
	"arguments": {
		
	}
}
CONCATENATE_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "concatenate",
	"action_output_var": "output",
	"arguments": {
		"concatenate_with_text": ""
	}
}
MATCH_ACTION_SAMPLE = {
	"action_input_var": "input/item",
	"action_type": "match",
	"action_output_var": "output",
	"arguments": {
		"re_pattern": "",
		"re_flags": [],
		"find_all": True
	}
}

#> sudo /Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install --target=/Library/AutoPkg/Python3/Python.framework/Versions/Current/lib/python3.7/site-packages/ --ignore-installed signify
__all__ = ["StringManipulator"]

class StringManipulator(UrlGetter):
	description = "Parse, manipulate, and return a string"
	input_variables = {
		"manipulation_actions": {
			"required": True,
			"description": (
				"An array of dictionaries representing the actions to take."
			)
		}
}
	output_variables = {
        
    }

	__doc__ = description


	def replace_text(self,input_variable_name:str = 'output',output_variable_name:str = 'output', options:dict = {"replacements":[]}) -> str:
		myString = self.env.get(input_variable_name, 'output')
		replacements = options["replacements"]
		if len(replacements) == 0:
			raise(ProcessorError('No replacements indicated.'))
		
		for replacement in replacements:
			nStrings = replacement["replace_n"] or -1
			searchString = replacement["find_text"]
			replaceString = replacement["replace_text"]
			myString = myString.replace(searchString,replaceString,nStrings)
			del nStrings,searchString,replaceString
		
		self.env[output_variable_name] = myString

	def main(self):
		actionFunctions = {
			"replace": self.replace_text
		}
		
		manipulationActions:array = self.env.get("manipulation_actions")
		if len(manipulationActions) == 0:
			raise(ProcessorError('No actions configured'))
		
		for manipulationAction in manipulationActions:
			self.output("Performing ({}) on string.".format(manipulationAction["action_type"]), verbose_level=3)
			inputVarName = self.env.get(manipulationAction["input_variable_name"], "output")
			outputVarName = self.env.get(manipulationAction["output_variable_name"], "output")
			self.env[outputVarName] = actionFunctions[manipulationAction["action_type"]](inputVarName,outputVarName,manipulationAction["options"])

		
if __name__ == "__main__":
	PROCESSOR = StringManipulator()
	PROCESSOR.execute_shell()
