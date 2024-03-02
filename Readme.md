# Threats To MITRE(CWD,ATT&CK) Mapper

**Program Design Purpose**: we want to use the AI-LLM to help to process the threats scenario description document such as (technical blog, CTI report, cyber attack training note) to summarize the attack flow path in the material, then parse the cyber attack behaviors from the attack and map each the single attack behaviors to the MITRE ATT&CK Matrix to find the related attack tactic and technique.   

Analyze the attack scenario and list the vulnerabilities could be found. Please use 

the following format:

vulnerability

You are a helpful assistant who help analyzing the attack scenario description and finding

the vulnerabilities. Match the vulnerabilities to the MITRE Common Weakness Enumeration and give 

a short explanation. Please list the matched MITRE CWE under the following format:

MITRE CWE: MITRE CWE-<number>

\- vulnerability: <vulnerability name>

\- explanation:  <Give a short summary about how the CWE match to the attack scenario>