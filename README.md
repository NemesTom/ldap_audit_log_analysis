# ldap_audit_log_analysis
 
In the "Performance Tuning for IBM Security Directory Server" IBM Redbook (https://www.redbooks.ibm.com/abstracts/redp4258.html?Open) there is an "itdsaudit.jar" file that provides some useful statistics on what is in the audit log. (example logfile is from the attachments of the Redbook as well) 
Using a decompiler I was able to look into the jar and it's classes and see what the code does, but I'm not that big on Java, I wanted something in Python.
This is the result. Does everything the original jar does and more. 

Use it like this for example: 

python ldap_audit_log_analysis.py

or like this:

python ldap_audit_log_analysis.py 'example.log' 

or like this:

python ldap_audit_log_analysis.py 'example.log' -performance

Calling just the python file defaults to analysing 'logfile.txt' in the script's folder.

The -performance switch displays data on how long the script ran and how many lines it processed.

As a general rule of thumb every ~500.000 line increases the runtime of the analysis by about
1.5 second, and the time it takes to analyze a logfile increases linearly with the number of lines. 
