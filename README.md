# CAPalyzer
CAPalyzer performs analysis of exported Conditional Access Policies (CAPs) - prefferably from dafthack's GraphRunner tool. It identifies security posture weaknesses such as policies in reporting-only mode, exclusions of users or groups, and missing recommended CAPs based on Microsoft's modern best practices.

Analyzes Conditional Access Policies exported via GraphRunner for common security posture weaknesses.
    Detects:
    - Policies still in "Reporting" mode
    - Excluded users or groups
    - Missing recommended CAPs from a supplied config file

  Usage:
  ```powershell -exec bypass
  CAPalyzer.ps1 [-CAPFile] <String> [-ConfigFile] <String> [[-OutFile] <String>] [<CommonParameters>]```
