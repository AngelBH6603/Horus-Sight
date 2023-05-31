Install-PackageProvider -name Nuget -Force      # Necesario para el resto de módulos a instalar
Install-Module NetworkingDSC -Force             # https://github.com/dsccommunity/NetworkingDsc
Install-Module ComputerManagementdsc -Force     # https://github.com/dsccommunity/ComputerManagementdsc
Install-Module ActiveDirectoryDSC -Force        # https://github.com/dsccommunity/ActiveDirectoryDSC