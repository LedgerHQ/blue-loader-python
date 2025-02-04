"""
*******************************************************************************
*   Ledger Blue
*   (c) 2023 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

import argparse
import os
from contextlib import contextmanager
from elftools.elf.elffile import ELFFile

__ELF_METADATA_SECTIONS = [
    "target",
    "target_name",
    "target_id",
    "app_name",
    "app_version",
    "api_level",
    "sdk_version",
    "sdk_name",
    "sdk_hash",
]


@contextmanager
def _get_elf_file(filename):
    if os.path.exists(filename):
        with open(filename, "rb") as fp:
            yield ELFFile(fp)
    else:
        raise FileNotFoundError(f"File {filename} does not exist.")


def _get_elf_section_value(elf, section_name):
    section = elf.get_section_by_name(f"ledger.{section_name}")
    section_value = ""
    if section:
        section_value = section.data().decode("utf-8").strip()
    return section_value


def get_elf_section_value(filename, section_name):
    with _get_elf_file(filename) as elf:
        return _get_elf_section_value(elf, section_name)


def get_target_id_from_elf(filename):
    return get_elf_section_value(filename, "target_id")


def get_argparser():
    parser = argparse.ArgumentParser(
        description="""Read the metadata of a Ledger device's ELF binary file."""
    )
    parser.add_argument(
        "--fileName", help="The name of the ELF binary file to read", required=True
    )
    parser.add_argument(
        "--section",
        help=f"The name of the metadata section to be read. If no value is provided, all sections are read.",
        choices=__ELF_METADATA_SECTIONS + ["all"],
        default="all",
    )
    return parser


if __name__ == "__main__":
    args = get_argparser().parse_args()

    with _get_elf_file(args.fileName) as elf:
        if args.section == "all":
            for section_name in __ELF_METADATA_SECTIONS:
                section_value = _get_elf_section_value(elf, section_name)
                print(f"{section_name} : {section_value}")
        else:
            print(_get_elf_section_value(elf, args.section))
