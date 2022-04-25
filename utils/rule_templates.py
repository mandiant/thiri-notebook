# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

""" 
------------------
| Rule Templates |
------------------
These templates are used by Engines in the utils.engines module. 

Use the following guidelines for new templates:
	Template Name		[rule_format]_[rule_type] e.g. yara or snort_http
	Rule Variables		Use format strings with {variable_names}. These can be filled out later like my_template.format(name='name', description='my rule')
	Comments			Add a # comment above each template with the Variable names accepted by your rule.
	Sub-Templates		Some formats (e.g. HXIOC) may require more complex templates. 
						Check hxioc, hxioc_processevent, and hxioc_group for an example of how these can be assembled.
"""
from datetime import datetime

""" 
---------
| HXIOC |
---------
"""
#Variables: name, description, guid_sid, logic
hxioc = """<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<OpenIOC xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://openioc.org/schemas/OpenIOC_1.1\" id=\"{guid_sid}\" last-modified=\""""+datetime.now().strftime("%Y-%m-%d%Z%H%M%S")+"""\" published-date=\"0001-01-01T00:00:01\">
	<metadata>
		<short_description>{name}</short_description>
		<description>{description}</description>
		<keywords/>
		<authored_by>auto-generated</authored_by>
		<authored_date>""" + datetime.now().strftime("%Y-%m-%d%Z%H%M%S") + """</authored_date>
	</metadata>
	<criteria>
		{logic}
	</criteria>
	<parameters/>
</OpenIOC>"""

#Variables: guid_indicator, condition, searchterm, field
hxioc_processevent = """        	<IndicatorItem id="{guid_indicator}" condition="{condition}" preserve-case="false" negate="false">
          		<Context document="processEvent" search="processEvent/{field}" type="event"/>
          		<Content type="string">{search_term}</Content>
        	</IndicatorItem>"""

#Variables: guid_operator, operator, conditions
hxioc_group = """<Indicator id="{guid_operator}" operator="{operator}">
{conditions}
    </Indicator>"""

""" 
---------
| Snort |
---------
"""
#Variables: name, anchor, logic
snort_http = """alert tcp any any -> any any (msg:\"{name}\"; content:\"T \"; offset:2; depth:3; content:{anchor};{logic} threshold:type limit, track by_src, count 1, seconds 1800; sid:<REPLACE_SID>; rev:1;)"""

""" 
--------
| Yara |
--------
"""
#Variables: name, description, logic
yara = """rule {name} {{
    meta:
        author="auto-generated"
        description="Auto-generated rule for: {description}"
        created=\""""+ datetime.now().strftime("%Y-%m-%d") +"""\"
        md5=""
        sid="1"
        rev="1" 
    {logic}
}}"""
