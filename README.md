# CAPalyzer
CAPalyzer performs analysis of exported Conditional Access Policies (CAPs) - prefferably from dafthack's GraphRunner tool (or from Graph Explorer - it should be json). It identifies security posture weaknesses such as policies in reporting-only mode, exclusions of users or groups, and missing recommended CAPs based on Microsoft's modern best practices.

Usage:
```
powershell -exec bypass
.\CAPalyzer.ps1 [-CAPFile] <String> [-ConfigFile] <String> [[-OutFile] <String>] [<CommonParameters>]
```
