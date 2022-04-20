# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

""" 
---------------------
| Input Definitions |
---------------------
This module defines the SearchTerm class and several sub-types including Keyword, Chain, and Anchor (sub-class of Keyword). 

Future input types should be implemented as a sub-class of SearchTerm or Keyword. 

REQUIRED PROPERTIES
    value           ->  type is not defined. usually this will be a UTF-8 bytes string.
    encoded         ->  dictionary with str keys and list of byte strings for values.
                    ->  used to hold encoded values like {"base64": ['r0']}

REQUIRED FUNCTIONS
    __init__        ->  initialize required properties + any others you add
    encode  ->  run provided encoder option and add encoded values to self.encoded dictionary
    get_enc_bytes   ->  accept encoding type (e.g. base64)
                    ->  return list of byte strings with that encoding
    get_enc_strings ->  accept encoding type (e.g. base64) 
                    ->  return list of strings with that encoding
    get_term        ->  return the property to be used for things like rule names and descriptions.
                    ->  for Chain this is self.name, for Keyword this is self.value

EXAMPLE USAGE
    chain = Chain("MyChain", ["test1", "test2"])
    obj = Anchor("JavaObj", b'\xac\xed')
    enc = 'base64'

    chain.encode(enc)
    print(f"Chain: {chain.get_enc_strings(enc)}")
    obj.encode(enc)
    print(f"Object: {obj.get_enc_strings(enc)}")

    rule = YaraRule(obj, chain, enc)
    rulename, rulecontent = rule.generate()
    print(f"Rule: {rulename}\n\n{rulecontent}")
"""

from abc import ABC, abstractmethod
from utils import encoders as Encoder
from typing import Callable, Union

""" 
------------------
| PARENT CLASSES |
------------------
"""
class SearchTerm(ABC):
    value = None
    encoded = dict[str, list[bytes]]

    @abstractmethod
    def encode(self, enc_type: str) -> None:
        ## Run provided encoder option and add encoded values to self.encoded dictionary
        raise NotImplementedError("Sub-classes of type SearchTerm must implement the encode() function.")

    @abstractmethod
    def get_enc_bytes(self, enc_type: str) -> Union[str, list[bytes]]:
        ## Accept encoding type (e.g. base64) and return list of byte strings with that encoding
        raise NotImplementedError("Sub-classes of type SearchTerm must implement the get_enc_bytes() function.")

    @abstractmethod
    def get_enc_strings(self, enc_type: str) -> Union[str, list[str]]:
        ## Accept encoding type (e.g. base64) and return list of strings with that encoding
        raise NotImplementedError("Sub-classes of type SearchTerm must implement the get_enc_strings() function.")

    def get_enc_types(self) -> list[str]:
        ## Return list of encoding types currently in the self.encoded dictionary
        return self.encoded.keys()

    @abstractmethod
    def get_term(self) -> str:
        ## Return the property to be used for things like rule names and descriptions.
        raise NotImplementedError("Sub-classes of type SearchTerm must implement the get_term() function.")

class Keyword(SearchTerm):
    value: bytes
    encoded: dict[str, list[bytes]]

    def __init__(self, value: Union[bytes,str]) -> None:
        self.value = value if isinstance(value, bytes) else bytes(value, 'utf-8')
        self.encoded = {}

    def encode(self, enc_type: str, enc_func: Callable[..., list[bytes]] = None) -> None:
        ## Run provided encoder option and add encoded values to self.encoded dictionary
        
        #Get function definition 
        if enc_func is None and Encoder.lookup(enc_type) is not None: 
            enc_func = Encoder.lookup(enc_type)
        elif enc_func is None: 
            raise RuntimeError(f"Could not find {enc_type} in the Encoder class.")

        # Create list/initialize key if necessary
        if enc_type not in self.encoded.keys():
            self.encoded[enc_type] = []

        # Add to dictionary
        self.encoded[enc_type].extend(enc_func(self.value))

    def get_enc_bytes(self, enc_type: str) -> list[bytes]:
        ## Accept encoding type (e.g. base64) and return list of byte strings with that encoding
        if enc_type not in self.encoded.keys():
            raise RuntimeError(f"{enc_type} not found in {self.get_term()} keyword encoded values.")

        return self.encoded[enc_type]

    def get_enc_strings(self, enc_type: str) -> list[str]:
        ## Accept encoding type (e.g. base64) and return list of strings with that encoding
        if enc_type not in self.encoded.keys():
            raise RuntimeError(f"{enc_type} not found in {self.get_term()} keyword encoded values.")

        enc_strings = []
        for e in self.encoded[enc_type]:
            try:
                e_clean = e.decode('ascii')
            except:
                e_clean = Encoder.util_raw_hex(e)

            enc_strings.append(e_clean)

        return enc_strings
        
    def get_term(self) -> str:
        ## Return the property to be used for things like rule names and descriptions.
        return Encoder.util_strip_special(self.value).lower().decode('ascii')

    def get_term_bytes(self) -> bytes:
        ## Return the property to be used for things like rule names and descriptions.
        return self.value

""" 
-----------------
| CHILD CLASSES |
-----------------
"""
class Chain(SearchTerm):
    name: str
    encoded: dict[str, list[bytes]]
    value: list[Keyword]

    def __init__(self, name: str, value: list[str]) -> None:
        self.name = name
        self.encoded = {}
        self.value = [Keyword(v) for v in value]

    def encode(self, enc_type: str) -> None:
        ## Run provided encoder option and add encoded values to self.encoded dictionary
        enc_func = Encoder.lookup(enc_type)

        if enc_func is None: 
            raise RuntimeError(f"Could not find {enc_type} in the Encoder class.")

        if enc_type not in self.encoded.keys():
            self.encoded[enc_type] = []

        self.encoded[enc_type].extend(enc_func(self.get_term_bytes()))

        for k in self.value: 
            k.encode(enc_type, enc_func)

    def get_enc_bytes(self, enc_type: str) -> list[bytes]:
        ## Accept encoding type (e.g. base64) and return list of byte strings with that encoding
        try:
            return [k.get_enc_bytes(enc_type) for k in self.value]

        except:
            raise RuntimeError(f"Could not get all encoded byte values for {self.get_term()} chain.")

    def get_enc_strings(self, enc_type: str) -> list[str]:
        ## Accept encoding type (e.g. base64) and return list of strings with that encoding
        try:
            return [k.get_enc_strings(enc_type) for k in self.value]

        except:
            raise RuntimeError(f"Could not get all encoded string values for {self.get_term()} chain.")

    def get_term(self) -> str:
        ## Return the property to be used for things like rule names and descriptions.
        return Encoder.util_strip_special(self.name)

    def get_term_bytes(self) -> bytes:
        ## Return the property to be used for things like rule names and descriptions.
        return bytes(self.name, 'utf-8')

class Anchor(Keyword):
    name: str

    def __init__(self, name: str, value: bytes) -> None:
        self.name = name
        super().__init__(value)
    
    def encode(self, enc_type: str) -> None:
        ## Run provided encoder option and add encoded values to self.encoded dictionary
        enc_func = Encoder.lookup(enc_type)

        if enc_func is None: 
            raise RuntimeError(f"Could not find {enc_type} in the Encoder class.")

        super().encode(enc_type, enc_func)

    def get_regex(self, enc_type: str) -> str:
        ## Return a regex pattern to be used for rule output
        temp = self.get_enc_strings(enc_type)[0]
        hexchar = "\\x"
        delim = "|" if hexchar in temp else '"'
        return f"{delim}{temp.replace(hexchar, ' ')}{delim}"

    def get_regex_raw_hex(self, enc_type: str) -> str:
        hexchar = "\\x"
        return f"|{Encoder.util_raw_hex(self.get_enc_strings(enc_type)[0]).replace(hexchar, ' ')}|"
 
    def get_term(self) -> str:
        ## Return the property to be used for things like rule names and descriptions.
        return Encoder.util_strip_special(self.name)

    def get_term_bytes(self) -> bytes:
        ## Return the property to be used for things like rule names and descriptions.
        return bytes(self.name, 'utf-8')