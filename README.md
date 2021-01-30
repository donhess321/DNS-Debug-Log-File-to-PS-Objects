# DNS-Debug-Log-File-to-PS-Objects

Read the DNS servers debug log file and parse each line to a Powershell object.  This can be run over a single file that is separated from the DNS server or run with the -t variable to watch for new lines added to the file.  If you want to watch the file, PSv3+ is required, otherwise PSv2 will be able to parse a single file.  Set the $DebugPreferences='Continue' to view any log lines that do match the regex used for parsing.  This is an "object out" companion script to my DNS to SQL via Powershell project.

![Output_example](https://github.com/donhess321/DNS-Debug-Log-File-to-PS-Objects/blob/main/Output_example.png)

This is a reposting from my Microsoft Technet Gallery.
