# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

""" 
-----------------
| Engine Module |
-----------------
This module includes functions that generate rules in different formats with varying options.

New classes should inherit the base class Engine. See TemplateClass for more details.
"""
from abc import ABC, abstractmethod
from enchant import Dict as Dictionary
from ipywidgets import widgets
from re import search as re_search
from sys import stderr
from typing import Callable, Union
from uuid import uuid4 as random_uuid
from utils import encoders as Encode
from utils import rule_templates
from utils.inputs import SearchTerm, Keyword, Chain, Anchor

class Engine(ABC):
    name : str
    description : str
    supported_formats : dict[str,Callable]
    
    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError("Must implement __init__()")

    def generate(self, custom_options: list[widgets]) -> (str, str):
        options = self.parse_options(custom_options)
        rule_format = options['Format']

        results = []

        for rf in rule_format:
            if rf in self.supported_formats:
                results.append(self.supported_formats[rf](options))
            else:
                print(f"\n[!] WARNING - {self.name} engine has not implemented the {rf} format yet.", file=stderr)
        
        return results

    @abstractmethod
    def get_custom_options(self, selected_type: str) -> list[widgets]:
        raise NotImplementedError("Must implement get_custom_options()")

    def get_formats(self) -> list[str]:
        return [*self.supported_formats]

    @abstractmethod 
    def get_input_type(self) -> [list[str], list[str], str]:
        raise NotImplementedError("Must implement get_input_type()")

    def get_name(self) -> str:
        return self.name

    @abstractmethod
    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,Anchor,SearchTerm]]:
        raise NotImplementedError("Must implement get_selected_options()")

class CodeCert(Engine):
    name = "CodeCert"

    def __init__(self) -> None:
        self.supported_formats = {
            "yara": self.generate_yara
        }

        self.description = f"""### {self.name} Engine
    Hunting rules for suspicious code signing certificates. 

    Supports: 
        - Yara rule (3.14 compatible)

    Currently only accepts certificate Serials and Subjects."""
        
    def generate_yara(self, options: dict[str, Union[str, Anchor, SearchTerm]]) -> (str, str):
        ## Generate Yara rule
        name = f"M_Methodology_HTTP_{self.name}_{options['Subject']}"
        logic = f'condition:\n\t\tfor any i in (0..pe.number_of_signatures-1) : (pe.signatures[i].serial == \'{options["Serial"].lower()}\' and pe.signatures[i].subject contains \'{options["Subject"]}\')'
        rule = f'import "pe"\n{rule_templates.yara.format(name=name, description=options["Subject"], logic=logic)}'
        
        return name, rule

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        input_widgets = [widgets.Text(
            placeholder='Enter : delimited serial',
            description='Serial',
            disabled=False
        )]

        input_widgets.append(widgets.Text(
            placeholder='Enter subject/CN',
            description='Subject',
            disabled=False
        ))

        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        return None, None, self.description

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        required = ["Serial", "Subject", "Format"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values

        if all(req in options for req in required):
            options["Serial"] = options["Serial"] if ":" in options["Serial"] else options["Serial"].replace(" ", ":")
            return options

        raise RuntimeError("Missing required option")

class DLLHijack(Engine):
    name = "DLLHijack"

    def __init__(self) -> None:
        self.supported_formats = {
            "yara - normal": self.generate_yara,
            "yara - VirusTotal": self.generate_yara_vt
        }

        self.description = f"""### {self.name} Engine
    Hunting rules for PE/DLLs with export names that can be used for DLL hijacking. 

    Supports: 
        - Yara rule (3.14 compatible)
        - Yara rule (VirusTotal compatible)

    Provide whitespace delimited exports and they will be OR'd. 

    Use the Edit Rule section to add any negations."""

    def generate_yara_vt(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        name, rule = self.generate_yara(options)
        return f'{name}_VirusTotal', f'{rule[0:-2]} and not signatures contains "Win32.Floxif" and not signatures contains "Win32.Ramnit"\n}}'

    def generate_yara(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        """ Generate your rule and return the rule name and content """
        clean = Encode.util_strip_special(options['Exports'][0])
        name = f"M_Methodology_{self.name}_{clean}"
        logic = " or ".join([f'pe.exports("{e}")' for e in options['Exports']])
        rule = 'import "pe"\n{}'.format(rule_templates.yara.format(name=name, description=clean, logic=f"condition:\n\t\t{logic}"))

        return name, rule

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        """ This function displays the inputs for your engine."""
        input_widgets = [widgets.Textarea(
            description='Exports',
            disabled=False
        )]

        # 'Format' is required.
        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        return None, None, self.description

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        """ This function returns a clean dictionary of option values from Jupyter inputs"""
        required = ["Exports", "Format"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        # Get all provided exports
        # I'm not going to do any encoding, so if someone submits non-ASCII values it's gonna break things. 
        options["Exports"] = options["Exports"].split()

        return options

class EndpointProcess(Engine):
    name = "EndpointProcess"

    def __init__(self) -> None:
        self.supported_formats = {
            "hxioc": self.generate_hxioc
        }

        self.description = f"""### {self.name} Engine
    Hunting rules for suspicious process executions

    Supports: 
        - HXIOC ProcessEvent (real-time)

    If you specify an encoding method, it will encode the provided Command Line Args only.
    This will allow the rules to match on Event Logs with unobfuscated process/user names and obfuscated commands."""

    def generate_hxioc(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        conditions = []

        #Add process name
        conditions.append(rule_templates.hxioc_processevent.format(
                    guid_indicator=str(random_uuid()), 
                    condition="contains", 
                    search_term=options['Process Name'], 
                    field="process"))

        #Add command line
        conditions.append(rule_templates.hxioc_processevent.format(
                    guid_indicator=str(random_uuid()), 
                    condition="contains", 
                    search_term=options['Command Line'], 
                    field="processCmdLine"))

        if 'Parent Process' in options:
            #Add parent process
            conditions.append(rule_templates.hxioc_processevent.format(
                        guid_indicator=str(random_uuid()), 
                        condition="contains", 
                        search_term=options['Parent Process'], 
                        field="parentProcess"))

        if 'User' in options:
            #Add parent process
            conditions.append(rule_templates.hxioc_processevent.format(
                        guid_indicator=str(random_uuid()), 
                        condition="contains", 
                        search_term=options['User'], 
                        field="username"))


        """ Generate your rule and return the rule name and content """
        rule = rule_templates.hxioc.format(
                    name=f"Suspicious {options['Process Name']} execution (METHODOLOGY)", 
                    description=f"{options['Process Name']} with the following arguments may be malicious: {options['Command Line'].get_term()}", 
                    logic=rule_templates.hxioc_group.format(guid_operator=str(random_uuid()), operator="AND", conditions="\n".join(conditions)), 
                    guid_sid=str(random_uuid())
                                        )
        return options['Process Name'], rule
        
    def get_custom_options(self, selected_type: str) -> list[widgets]:
        """ This function displays the inputs for your engine. 

        Each description will later be used as a reference name to retrieve the options.

        Add them to the list in the order you would like them displayed.

        Format is *required* as an input. This is used by the Engine.generate() function.
        """
        input_widgets = [widgets.Text(
            placeholder='(required) Short description',
            description='Title',
            disabled=False
        )]

        input_widgets.append(widgets.Text(
            placeholder='(required) Full description',
            description='Description',
            disabled=False
        ))

        input_widgets.append(widgets.Dropdown(
            options=Encode.list(),
            description='Encoder',
            disabled=False
        ))

        input_widgets.append(widgets.Text(
            placeholder='(optional) NT USER\\SYSTEM',
            description='User Name',
            disabled=False
        ))
        
        input_widgets.append(widgets.Text(
            placeholder='(optional) powershell.exe',
            description='Parent Process',
            disabled=False
        ))

        input_widgets.append(widgets.Text(
            placeholder='(required) cmd.exe',
            description='Process Name',
            disabled=False
        ))

        input_widgets.append(widgets.Text(
            placeholder='(required) cmd /c net user Administrator',
            description='Command Line',
            disabled=False
        ))

        # 'Format' is required.
        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        return None, None, self.description

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        """ This function returns a clean dictionary of option values from Jupyter inputs

        It is called by Engine.generate() and passed to the child class (engine's) generate_{format}() functions. 
            -> Again, "Format" is required by this function

        The keys in clean{} must exactly match the description used for the input widgets. 

        Do any object instantiation, encoding, etc. necessary on the options in this workflow. 
        """
        required = ["Title", "Description", "Process Name", "Command Line", "Format"]
        ### optional = ["Encoder", "User Name", "Parent Process"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        options['Command Line'] = Keyword(options['Command Line'])
        options['Command Line'].encode(options['Encoder'])

        return options

class PDBPath(Engine):
    name = "PDBPath"

    def __init__(self) -> None:
        self.supported_formats = {
            "yara": self.generate_yara
        }
        
        self.description = f"""### {self.name} Engine
    Hunting rules for PE/DLLs with suspicious PDB Paths

    Supports: 
        - Yara rule (3.14 compatible)

    Supports individual keywords or a chain of ordered keywords. The Chain Name is only used for the rule name."""

    def generate_yara(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        ## Generate Yara rule
        enc_strings = options['Input'].get_enc_strings('plain')
        
        if len(enc_strings) == 0:
            raise RuntimeError("Could not get input strings")
        
        regex = enc_strings[0] if isinstance(enc_strings[0], str) else enc_strings[0][0]
        
        if len(enc_strings) > 1:
            for es in enc_strings[1:]:
                regex = f"{regex}.{{0,250}}{es[0]}"
        
        name = f"M_Methodology_PDBPath_{options['Input'].get_term()}"
        logic = f"strings:\n\t\t$anchor = \"RSDS\"\n\t\t$pcre = /RSDS[\\x00-\\xFF]{{20}}[a-zA-Z]:\\\\.{{0,250}}{regex}.{{0,250}}\\.pdb\\x00/ nocase\n\tcondition:\n\t\t(uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $anchor and $pcre"

        return name, rule_templates.yara.format(name=name, description=options['Input'].get_term(), logic=logic)

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        input_widgets = [widgets.Text(
            placeholder='Enter searchterm',
            description='Search Term',
            disabled=False
        )]

        if selected_type ==  "Chain":
            input_widgets[0].placeholder = "Enter keywords in order as one string. separated by +"
            input_widgets.insert(0, widgets.Text(
                description='Chain Name',
                disabled=False
            ))

        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        opts =  ['Key', 'Chain']
        tips = ["Single search term", "Ordered list of keywords"]

        return opts, tips, self.description 

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        """ This function returns a clean dictionary of option values from Jupyter inputs

        It is called by Engine.generate() and passed to the child class (engine's) generate_{format}() functions. 
            -> Again, "Format" is required by this function

        The keys in clean{} must exactly match the description used for the input widgets. 

        Do any object instantiation, encoding, etc. necessary on the options in this workflow. 
        """
        required = ["Search Term", "Format"]
        ### optional = ["Chain Name"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        if 'Chain Name' in options:
            options['Input'] = Chain(options['Chain Name'], options['Search Term'].split("+"))
        else:
            options['Input'] = Keyword(options['Search Term'])

        options['Input'].encode('plain')

        return options

class SerializedObject(Engine):
    name = "SerializedObject"
    anchors = {
        "JavaObj": Anchor("JavaObj", b'\xac\xed'),
        "JNDIObj": Anchor("JNDIObj", b'\x24\x7b\x6a\x6e\x64\x69\x3a'),
        "PHPObj": Anchor("PHPObj", b'\x4f\x3a'),
        "PythonPickle": Anchor("PythonPickle", b'\x80\x04\x95'),
        "NETGeneric": Anchor("NETGeneric" , b'\x74\x79\x70\x65'),
        "NETObject": Anchor("NETObject" , b'\x00\x01\x00\x00\x00'),
        "NETJavaScript": Anchor("NETJavaScript", b'\x5f\x74\x79\x70\x65'),
        "NETSharpBinary": Anchor("NETSharpBinary", b'\x01\x06\x01'),
        "NETSharpXML": Anchor("NETSharpXML" , b'\x79\x70\x65'),
        "NETSOAP": Anchor("NETSOAP", b'\x3c\x53\x4f\x41\x50'),
        "NETViewState": Anchor("NETViewState",b'\xff\x01'),
        "YSoSerialNET": Anchor("YSoSerialNET",b'\xff\xfe')
    }

    def __init__(self) -> None:
        self.supported_formats = {
            "snort": self.generate_snort,
            "yara": self.generate_yara
        }

        self.description = """### {name} Engine
    Hunting rules for serialized objects 

    Supports: 
        - Snort
        - Yara rule (3.14 compatible)

    Languages:
        - {anchors}

    See HeySerial for more details: 
        - https://www.mandiant.com/resources/hunting-deserialization-exploits
        - https://github.com/mandiant/heyserial/
    """.format(name=self.name, anchors='\n\t\t- '.join(self.anchors.keys()))

    def generate_snort(self, options: dict[str, Union[str, Anchor, SearchTerm]]) -> (str, str):
        search_term = options['Input']

        ## Generate Snort rule with all encoded search term strings
        regex = ""
        for term in search_term.get_enc_strings(options['Encoder']):
            # If it's a list of lists, it's a chain. Group terms in regex
            if isinstance(term, list):
                joined = '|'.join(term).replace('/', '\/')
                regex = f"{regex} pcre:\"/({joined})/Rs\";"
 
            # If it's a list of strings, it's a keyword/generic searchterm
            else:
                # Use a bytes search term | 00 01 | if string has \x encoded bytes
                # Use a plain string term " a a " if it's a plain string
                delim = "|" if "\\x" in term else ''
                term = term.replace("\\x", " ")
                
                regex = f"{regex} content:\"{delim}{term}{delim}\"; distance:0;"

        # Fill in templates
        anc_regex = options['Anchor'].get_regex(options['Encoder'])
        name = f"M.Methodology.HTTP.{self.name}.{options['Anchor'].get_term()}.{search_term.get_term()}.[{options['Encoder']}]"

        return name, rule_templates.snort_http.format(name=name, anchor=anc_regex, logic=regex)

    def generate_yara(self, options: dict[str, Union[str, Anchor, SearchTerm]]) -> (str, str):
        ## Generate Yara rule with all encoded search term strings
        search_term = options['Input']
        
        # Set counter and starting condition/regex values
        counter = 0
        condition = "@anchor[1] < @pattern[1]" if isinstance(search_term, Chain) else "$anchor"
        regex = "\n\t\t$pattern = /" if isinstance(search_term, Chain) else ""

        # Loop through all encoded strings
        for term in search_term.get_enc_strings(options['Encoder']):
            # If it's a list of lists, it's a chain. Group terms in regex
            if isinstance(term, list):
                sep = ".{255}" if counter > 0 else ""
                regex = f"{regex}{sep}({'|'.join(term)})"
            
            # If it's a list of strings, it's a keyword/generic searchterm
            else:
                # Use a bytes search term | 00 01 | if string has \x encoded bytes
                # Use a plain string term " a a " if it's a plain string
                delim = "|" if "\\x" in term else '"'
                term = term.replace("\\x", " ")
                regex = f"{regex}\n\t\t$keyword{counter} = {delim}{term}{delim}"
                
                # Build the condition so they're sequenced
                condition = f"{condition} and (@keyword0[1] > @anchor[1])" if counter == 0 else f"{condition} and (@keyword{counter}[1] > @keyword{counter-1}[1])"
            
            counter += 1

        # Complete the regex if it's a chain Object
        if isinstance(search_term, Chain):
            regex = regex + "/"

        # Put the rule together and return it 
        name = f'M_Methodology_HTTP_{self.name}_{options["Anchor"].get_term()}_{search_term.get_term()}_{options["Encoder"]}'
        logic = f'strings:\n\t\t$anchor={options["Anchor"].get_regex(options["Encoder"])}{regex}\n\tcondition:\n\t\t{condition}'

        return name, rule_templates.yara.format(name=name, description=search_term.get_term(), logic=logic)

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        if selected_type ==  "Chain":
            input_widgets = [widgets.Text(
                description='Chain Name',
                disabled=False
            )]
            
            input_widgets.append(widgets.Text(
                description='Search Term',
                placeholder="Enter searchterms delimited with '+'",
                disabled=False
            ))

        else:
            input_widgets = [widgets.Text(
                placeholder='Enter searchterm',
                description='Search Term',
                disabled=False
            )]

        input_widgets.append(widgets.Dropdown(
            options=Encode.list(),
            description='Encoder',
            disabled=False
        ))

        input_widgets.append(widgets.Dropdown(
            options=[*self.anchors],
            description='Language',
            disabled=False
        ))


        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        opts =  ['Key', 'Chain']
        tips = ["Single search term", "Ordered list of keywords"]

        return opts, tips, self.description 

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        required = ["Language", "Search Term", "Encoder", "Format"]
        ### optional = ["Chain Name"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        # Do setup
        options["Anchor"] = self.anchors[options['Language']]
        options["Anchor"].encode(options['Encoder'])    

        if 'Chain Name' in options:
            options['Input'] = Chain(options['Chain Name'], options['Search Term'].split("+"))
        else:
            options['Input'] = Keyword(options['Search Term'])

        options['Input'].encode(options['Encoder'])

        return options

class SwearWord(Engine):
    name = "SwearWord"

    def __init__(self) -> None:
        self.anchors = {
            "pe": (Anchor("pe", b"\x50\x45\x00\x00"), "0x3c"),
            "elf": (Anchor("elf", b"\x7f\x45\x4c\x46"), "0x00")
        }

        self.alt_endings = ["ch","ches","e","ed","er","es","est",
                            "ies","ing","man","men","s","ses","sh",
                            "shes","x","xes","y","z","zes"]


        self.description = """### {name} Engine
    Hunting rules for swear words (or generally suspicious terms)

    Supports: 
        - Yara rule (3.14 compatible)

    File Types:
        - {anchors}

    If the provided term is an English word, THIRI will also generate and include related words with the same root and different endings. 

    For example: "think" would be expanded to ['think', 'thinker', 'thinking', 'thinks']
        """.format(name=self.name, anchors='\n\t\t- '.join(self.anchors.keys()))

        # This is the PyEnchant dictionary
        self.is_english = Dictionary("en-US").check

        # You can define exceptions as a list of Anchors if you find repeat offending file signatures you want to exclude.
        self.exceptions = [
            
        ]

        self.supported_formats = {
            "yara": self.generate_yara
        }

    def generate_snort(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        """ Generate your rule and return the rule name and content """
        return "Rule Name", f"Rule Content {options['Option1']}"
        
    def generate_yara(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        """ Generate your rule and return the rule name and content"""
        search_term = options['Input']
        
        # Build search term regex
        modifier = "ascii nocase wide" if "base" not in options['Encoder'] else "ascii wide" #Base64 is case sensitive
        group = []
        for term in search_term:
            group.extend(term.get_enc_strings(options['Encoder']))
        regex = f"$search_{search_term[0].get_term()} = /[^A-Za-z]{{1}}({'|'.join(group)})[^A-Za-z]{{1}}/ {modifier}"

        # Build exceptions regex
        exceptions = "\n\t\t".join([f"${e.get_term()} = {e.get_regex(options['Encoder'])} ascii wide" for e in self.exceptions])

        # Set counter and starting condition/regex values
        condition = f'$filetype at {options["Anchor"][1]} and $search_{search_term[0].get_term()} and not {" and not ".join([f"${e.get_term()}" for e in self.exceptions])}'

        # Put the rule together and return it 
        name = f'M_Methodology_{self.name}_{options["Anchor"][0].get_term()}_{search_term[0].get_term()}_{options["Encoder"]}'
        ## the [1:-1] will trim off the |'s, so we can use Yara hex syntax of {}. Issue #3
        logic = f'strings:\n\t\t$filetype= {{{options["Anchor"][0].get_regex_raw_hex(options["Encoder"])[1:-1]}}}\n\t\t{regex}\n\t\t{exceptions}\n\tcondition:\n\t\t{condition}'

        return name, rule_templates.yara.format(name=name, description=', '.join([x.get_term() for x in search_term]), logic=logic)

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        """ This function displays the inputs for your engine. """
        input_widgets = [widgets.Text(
            placeholder='Enter text',
            description='Search Term',
            disabled=False
        )]

        input_widgets.append(widgets.Dropdown(
            options=Encode.list(),
            description='Encoder',
            disabled=False
        ))

        input_widgets.append(widgets.Dropdown(
                options=[*self.anchors],
                description='FileType',
                disabled=False
        ))

        # 'Format' is required.
        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        return None, None, self.description

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        """ This function returns a clean dictionary of option values from Jupyter inputs"""
        required = ["Search Term", "Encoder", "FileType", "Format"]
        ### optional = ["Option3"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        # Add FileType as an Anchor
        options["Anchor"] = self.anchors[options['FileType']]
        options["Anchor"][0].encode(options['Encoder'])    

        # Add provided searchterm
        options['Input'] = [Keyword(options['Search Term'])]
        options['Input'][0].encode(options['Encoder'])

        # Add variations if it's an english word
        if self.is_english(options['Search Term']):
            for end in self.alt_endings:
                if self.is_english(f"{options['Search Term']}{end}"):
                    options['Input'].append(Keyword(f"{options['Search Term']}{end}"))
                    options['Input'][-1].encode(options['Encoder'])

        for ex in self.exceptions:
            ex.encode(options['Encoder'])

        return options

class TemplateClass(Engine):
    name = "TemplateClass"

    def __init__(self) -> None:
        self.description = f"""### {self.name} Engine
        Document your engine in Markdown. Set in your __init__

        Include 
            - explanations
            - pro tips
            - examples"""

        self.supported_formats = {
            "snort": self.generate_snort,
            "yara": self.generate_yara
        }

    def generate_snort(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        """ Generate your rule and return the rule name and content """
        return "Rule Name", f"Rule Content {options['Option1']}"
        
    def generate_yara(self, options: dict[str, Union[str, SearchTerm]]) -> (str, str):
        """ Generate your rule and return the rule name and content """
        return "Rule Name", f"Rule Content {options['Option1']}"

    def get_custom_options(self, selected_type: str) -> list[widgets]:
        """ This function displays the inputs for your engine. 

        Each description will later be used as a reference name to retrieve the options.

        Add them to the list in the order you would like them displayed.

        Format is *required* as an input. This is used by the Engine.generate() function.
        """
        input_widgets = [widgets.Text(
            placeholder='Enter text',
            description='Option1',
            disabled=False
        )]

        input_widgets.append(widgets.Text(
            placeholder='Enter more text',
            description='Option2',
            disabled=False
        ))

        # 'Format' is required.
        input_widgets.append(widgets.SelectMultiple(
                options=[*self.supported_formats],
                description='Format',
                disabled=False
        ))

        return input_widgets

    def get_input_type(self) -> [list[str], list[str], str]:
        """ This function is called before custom_options are retrieved.
        It will create a Jupyter Toggle button input where 
            -> options = first returned list
            -> tips for provided options = second return list

        This will be passed to get_custom_options when called. 

        It can be ignored or used to affect the flow of your engine.
        """
        return None, None, self.description

    def parse_options(self, options: dict[str, str]) -> dict[str, Union[str,SearchTerm]]:
        """ This function returns a clean dictionary of option values from Jupyter inputs

        It is called by Engine.generate() and passed to the child class (engine's) generate_{format}() functions. 
            -> Again, "Format" is required by this function

        The keys in clean{} must exactly match the description used for the input widgets. 

        Do any object instantiation, encoding, etc. necessary on the options in this workflow. 
        """
        required = ["Option1", "Option2", "Format"]
        ### optional = ["Option3"]
        options = {k:v for k,v in options.items() if v} #Get rid of empty values
        
        # Check for required options
        if not all(req in options for req in required):
            raise RuntimeError("Missing required option")

        return options
