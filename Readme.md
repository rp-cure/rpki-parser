# RPKI-Parser
This tool allows to parse all common RPKI objects with a custom version of the asn1crypto library.
To use the tool, a modified version of asn1crypto must be installed. The modified version is included in this repo. Use pip install ./asn1crypto-1.5.2.tar.gz for installation.
Execute parsing.py to parse arbitrary objects. The repository contains examples of all common RPKI objects for demonstration.
You may use a debugger to investigate the content of the parsed objects.
If you have any questions, feel free to open an issue. 

# Who is this tool for
This tool may be used by anyone working with RPKI objects, including researchers, developers and operators. The tool can be easily extended.

# Acknowledgment
This tool and the adaption of the asn1crypto library was developed by Fraunhofer SIT and the ATHENE Center for applied Cybersecurity Research
