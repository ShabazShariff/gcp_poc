# Configuration Definition
Configuration os_hardening {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
        AccountPolicy AccountPolicies 
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-36286-3
            # DataSource: Security Policy
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'

            # CceId: CCE-37063-5
            # DataSource: Security Policy
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-37432-2
            # DataSource: Security Policy
            # Ensure 'Accounts: Guest account status' is set to 'Disabled' 
            #Accounts_Guest_account_status = 'Disabled'


            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = '14'

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = '2'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            #  Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                     = '24'

            # CceId: CCE-37167-4
            # DataSource: Security Policy
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = '50'
        }
	SecurityOption AccountSecurityOptions {
            Name                                   = 'AccountSecurityOptions'

        # CceId: CCE-36056-0
        # DataSource: Registry Policy
        # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
        # Interactive_logon_Do_not_display_last_user_name      = 'Enabled'

	# CceId: CCE-37863-8
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers          = 'Disabled'

	 # CceId: CCE-37972-7
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
        Microsoft_network_server_Disconnect_clients_when_logon_hours_expire                    = 'Enabled'

	    # CceId: CCE-37701-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
        Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'

        # CceId: CCE-37942-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
        Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'

	# CceId: CCE-38046-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
		
	}
	 # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Ensure 'Audit Audit Policy Change' is set to include 'Success'
        AuditPolicySubcategory 'Audit Audit Policy Change (Success)' {
            Name      = 'Audit Policy change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
	# CceId: CCE-37132-8
        # DataSource: Audit Policy
        # Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
	# CceId: CCE-36267-3
        # DataSource: Audit Policy
        # Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
           Name      = 'Sensitive Privilege Use'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
	# CceId: CCE-37856-2
        # DataSource: Audit Policy
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
           Name      = 'User Account Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
	# CceId: CCE-38114-5
        # DataSource: Audit Policy
        # Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
           Name      = 'Security State Change'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
	# CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
        Registry 'NullSessionShares' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionShares'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36173-3
        # DataSource: Registry Policy
        # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'LmCompatibilityLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'DWord'
            ValueData = '5'
        }

        # CceId: CCE-37835-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinServerSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinServerSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: CCE-37553-5 
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinClientSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinClientSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }



        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: CCE-36863-9 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
        Registry 'EnableUIADesktopToggle' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableUIADesktopToggle'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'AllowCortana' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Enable 'Turn on behavior monitoring'
        Registry 'DisableBehaviorMonitoring' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Enable 'Send file samples when further analysis is required' for 'Send Safe Samples'
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Scan removable drives' is set to 'Enabled'
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Detect change from default RDP port' is configured
        Registry 'PortNumber' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp'
            ValueName = 'PortNumber'
            ValueType = 'DWord'
            ValueData = '3389'
        }
	# CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'AllowSearchToUseLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            ValueData = '0'
        }

       

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Enabled'
        Registry 'ClearPageFileAtShutdown' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
            ValueName = 'ClearPageFileAtShutdown'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
        Registry 'AllowAllPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'
            ValueName = 'AllowAllPaths'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36864-7
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'ConsentPromptBehaviorUser' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorUser'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Specify the interval to check for definition updates' is set to 'Enabled:1'
        Registry 'SignatureUpdateInterval' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
            ValueName = 'SignatureUpdateInterval'
            ValueType = 'DWord'
            ValueData = '8'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }



    }
}
os_hardening