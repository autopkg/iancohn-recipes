#!/usr/local/autopkg/python
# pylint: disable=invalid-name
# -*- coding: utf-8 -*-
#
# Copyright 2026 Ian Cohn
# https://www.github.com/autopkg/iancohn-recipes
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

import os.path
import sys

# to use a base module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
sys.path.insert(0, os.path.dirname(__file__))

from IntuneLib.IntuneWinCreatorBase import (  # pylint: disable=import-error, wrong-import-position
    IntuneWinCreatorBase,
)

__all__ = ["IntuneWinCreator"]

class IntuneWinCreator(IntuneWinCreatorBase):
    description = """Create an IntuneWin compressed file from a directory
    """
    input_variables = {
        "intunewin_source_folder": {
            "required": True,
            "description": "The path to the directory from which to create the IntuneWin file",
        },
        "intunewin_setup_file": {
            "required": True,
            "description": "The setup file included in the archive. Can be an MSI,PS1, or EXE file",
        },
        "intunewin_output_filename": {
            "required": False,
            "description": (
                "The desired base filename of the output IntuneWin file. "
                "If not specified, defaults to the base name of the setup file"
            ),
        },
        "intunewin_output_folder": {
            "required": False,
            "description": (
                "The folder in which to place the created IntuneWin file. "
                "If not specified, defaults to %RECIPE_CACHE_DIR%"
            ),
        },
        "intunewin_overwrite": {
            "required": False,
            "description": "If True, overwrite an existing file at the output location",
            "default": False,
        },
    }
    output_variables = {
        "intunewin_filepath": {
            "description": "The full path to the created file"
        },
        "intunewin_unencrypted_filesize": {
            "description": "The filesize of the unencrypted intunewin archive"
        },

    }
    
    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = IntuneWinCreator()
    PROCESSOR.execute_shell()
