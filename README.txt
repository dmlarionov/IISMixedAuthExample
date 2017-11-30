1) Execute as administrator:

%windir%\system32\inetsrv\appcmd.exe unlock config /section:windowsAuthentication
%windir%\system32\inetsrv\appcmd.exe unlock config /section:anonymousAuthentication


Or open in Notepad (as administrator) %windir%\system32\inetsrv\config\applicationHost.config and set overrideModeDefault="Allow" where appropiate.

2) Create IIS web site at port 5200, deploy and run SecurityTokenService there. Open http://localhost:5200 to see "Security Token Service is running.".

3) Create IIS web site at port 80, deploy and run WebApplication1. Then:

Open http://localhost/test/Open to make sure, that current principal is unauthenticated.
Open http://localhost/test/WinAuth1 or http://localhost/test/WinAuth2 to pass windows authentication and see principal.
Open http://localhost/test/FedAuth1 or http://localhost/test/FedAuth2 to pass federated authentication and see principal.
Open http://localhost/test/Open to make sure, that federatively authenticated user keeps authenticated on URLs, that doesn't require authorization.