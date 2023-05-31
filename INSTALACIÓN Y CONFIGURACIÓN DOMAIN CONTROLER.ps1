param(
            [string] $Dominio="energy.priv",          	 #Nombre del dominio a montar
            [string] $nombreDC1="Energy-DC",             #Nombre a poner en el primer controlador de dominio
            [string] $ipv4DC1='192.168.15.101',        	 #Ip del primer controlador
            [string] $ipv4GW='192.168.15.254',           #Puerta de Enlace
            [string] $sPass="Angel6603"                  #Password del administrador
)

$carpetaRaizDSC=$env:TEMP + "\DSC_ASO"
mkdir $carpetaRaizDSC #New-Item -Name $carpetaRaizDSC -ItemType: Directory -ErrorAction: SilentlyContinue
Set-Location $carpetaRaizDSC


#Borra DSCs que ya hubiera en el equipo
Remove-DscConfigurationDocument -Stage Previous, Pending, Current #Borramos cualquier trabajo DSC que haya habido, esté pendiente, o ejecutándose

[DSCLocalConfigurationManager()]configuration LCMConfig
{
    Node localhost
    {
        settings
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }
    }
}
LCMConfig
Set-DscLocalConfigurationManager -ComputerName localhost -Force -Verbose -path .\LCMConfig

$configData = @{
     AllNodes = @(
        @{
             NodeName = 'localhost';
             PSDscAllowPlainTextPassword = $true
         }
                 )
               }
Configuration ConfiguraPrimerDC{
    param(
            [string[]] $ComputerName ="localhost",
            [Parameter(Mandatory)][string[]] $ipv4 ,
            [Parameter(Mandatory)][string] $ipv4gt ,
            [Parameter(Mandatory)][string] $NuevoNombreEquipo,
            [Parameter(Mandatory)][string] $Dominio,
            [Parameter()][System.Management.Automation.PSCredential] $CredencialAdmin

)
    Import-DscResource -Module PSDesiredStateConfiguration    
    Import-DscResource -Module ComputerManagementdsc   
    Import-DscResource -Module NetworkingDSC
    Import-DscResource -Module ActiveDirectoryDSC
    Node $ComputerName{
        #####Configuración de red (usando NetworkingDSC)###############
        NetIPInterface DeshabilitaDHCP
        {
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Dhcp           = 'Disabled'
        }
        
        IPAddress DireccionIPV4
        {
            IPAddress      = $ipv4
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPV4'
        }
        DnsServerAddress ServidoresDNS
        {
            Address        = '1.1.1.1', '8.8.8.8'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
        }
        DefaultGatewayAddress PuertaDeEnlaceIPv4
        {
            Address        = $ipv4gt
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
        }
        
        #Preferencia de IPv4 sobre IPv6
        #https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/configure-ipv6-in-windows
        #reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters“ /v DisabledComponents /t REG_DWORD /d 32 /f
        #https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/windows/registryresource?view=dsc-1.1
        Registry IPv4preferidosobreIPv6
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            ValueName   = "DisabledComponents"
            ValueType   = "Dword"
            ValueData   = 32
            Force       = $true
        }
        #todo : ipv4 over ipv6
        #####FinConfiguración de red (usando NetworkingDSC)###############        
        Computer NuevoNombreDeEquipo {
            Name = $NuevoNombreEquipo
        }

        #############Configuración como controlador de Dominio
        ##Fuente:  https://www.altf4-formation.fr/comment-installer-active-directory-via-powershell-dsc
        
        WindowsFeature InstalaRolAD-DS { 
            DependsOn= '[Computer]NuevoNombreDeEquipo'
            Ensure = 'Present'
            Name = 'AD-Domain-Services'
            IncludeAllSubFeature = $true
        }

        WindowsFeature InstalaRolRSAT {
            DependsOn= '[WindowsFeature]InstalaRolAD-DS'
            Ensure = 'Present'
            Name = 'RSAT-AD-Tools'
            IncludeAllSubFeature = $true
        }
        
        ADDomain ConfiguraDominio {
            DependsOn ='[WindowsFeature]InstalaRolRSAT'
            Credential = $CredencialAdmin
            DomainName = $Dominio
            SafemodeAdministratorPassword = $CredencialAdmin
            ForestMode = 'WinThreshold'
        }
        #Por hacer:  comprobar configuracion DNS
    }
}


$passwd = ConvertTo-SecureString $sPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('administrador',$passwd)


ConfiguraPrimerDC -ConfigurationData $configData -ipv4 $ipv4DC1 -ipv4gt $ipv4GW -NuevoNombreEquipo $nombreDC1 -dominio $Dominio -CredencialAdmin $cred 
$dsc=Start-DscConfiguration -path ".\ConfiguraPrimerDC\" -Force -Verbose

###Posibles comprobaciones
##Get-DscConfigurationStatus|ft
##Get-DscConfiguration|ft -Properties ConfigurationName, ResourceId, DependsOn
##Get-NetIPConfiguration
##$env:COMPUTERNAME

