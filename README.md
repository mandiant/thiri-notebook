# thiri-notebook
Threat Hunting In Rapid Iterations

```
Author:     Alyssa Rahman (@ramen0x3f)
Created:    2022-01-20
Updated:    2022-02-12
```

## Why THIRI? 
_There's endless amounts of threat actor activity, malware, and infrastructure that needs to be detected and hunted down. A daunting task for sure._

Threat hunting often involves creating and searching for "weak signals" (aka hunting rules) looking for interesting techniques or anomalies that may be malicious. While weak signals are usually low fidelity (may have a high false positive rate), layering these signals together can surface really interesting activity!

_THIRI is an attempt to make this type of weak signal/hunting rule development more seamless._

**Why Jupyter?** - Jupyter notebooks proved to fit into our research workflows better, because they allow for dynamically building and tinkering with rules. 

Since THIRI is a notebook, it's also got built-in documentation. We recommend running it and trying out different selections to see how everything works! 

### Important Concepts
THIRI structures it's rule prototyping around "template engines" (or engines). These are basically different artifact types (e.g. Serialized Objects, PDB Paths, Process Execution). THIRI will automatically discover/load all defined engines on launch. 

![image](https://ghe.eng.fireeye.com/storage/user/1414/files/26ed50fd-36ab-4de4-866f-451ca0c47e00)

Each template rengine is a class defined in utils/engines.py and defines its own
* Description/Metadata
  * Rendered by THIRI as markdown when selected
![image](https://ghe.eng.fireeye.com/storage/user/1414/files/aafa3fed-3ed0-4328-ae2c-5d485c601cd1)

* Accepted Inputs
  * Each engine provides a list of Jupyter widgets which THIRI renders and returns
  * The engine also contains custom validation logic
  * THIRI supports variable inputs (e.g. allowing different input boxes based on an initial selection)

![image](https://ghe.eng.fireeye.com/storage/user/1414/files/fa208503-deda-45ec-845c-be88fd3fd0ce)
![image](https://ghe.eng.fireeye.com/storage/user/1414/files/aeb32099-16b4-4838-a765-ce5e213ebd50)

* Accepted Encoding Methods
  * Engines can generate rules with default options or using supported encoding methods
  * Encoders are defined in utils/encoders.py

![image](https://ghe.eng.fireeye.com/storage/user/1414/files/260e627b-7d4f-468a-8480-e41b1c15fbd5)

* Rule format outputs
  * Engines load basic templates from utils/rule_templates.py and populate them (e.g. Snort, Yara, HXIOC)
  * Currently rules are displayed in THIRI with an edit box for tweaking

![image](https://ghe.eng.fireeye.com/storage/user/1414/files/488007a7-40c5-408c-9c5f-bc1d76074e11) 
![image](https://ghe.eng.fireeye.com/storage/user/1414/files/dfe07412-171d-4248-83f8-6d1684e283a7)

### Expansion
Adding to THIRI is really simple and primarily involves adding to the scripts in the utils/ folder. 

#### Template Engines 
Check out TemplateClass in engines.py to get started making your own! 

No need to update THIRI. It will automatically discover/load your class next time it launches.

#### Encoders
These can be as simple or as complex as you'd like them to be. As long as it accepts a bytes object and returns a list of bytes objects, it'll work out of the box. 

#### Inputs 
If you've seen [HeySerial](https://github.com/mandiant/heyserial), some of this may look familiar to you. Engines can have whatever inputs they want, but we've created some helper classes in inputs.py to make encoding simple.
* Keyword - single search term
* Chain - list of Keyword objects
* Anchor - child of Keyword, similar but has some special cases for regex patterns and escaping

#### Rule Templates 
rule_templates.py has several formats to get you started, but adding templates is as simple as adding a format string variable. 

To use it, just import/reference it from your engine. 

## Setup
Required: Python 3.10+

Clone this repo and run the following from the thiri-notebook directory. 

### Install pre-reqs
```
# Create virtual environment
python3 -m venv thiri-env

# Activate (choose compatible command)
.\thiri-env\Scripts\activate #Windows
. ./thiri-env/bin/activate #Linux

# Install requirements with pip and jupyter
pip3 install -r REQUIREMENTS.txt
jupyter contrib nbextension install --user
```
For non-Windows systems, please also install the extra libraries needed for PyEnchant as documented here: https://pyenchant.github.io/pyenchant/install.html

### Launch Jupyter
```jupyter notebook --autoreload```

#### Configure extensions
* Click Nbextensions tab
* Uncheck "disable configuration"
* Check "Hide input"
* Check "Initialization Cells"

#### Open notebook
* Double click on notebook in Files tab
* Click the eye button on the far right of the top toolbar to hide code inputs
* Click the calculator button to run the first cell
* Cells should update dynamically

# License
```# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.```
