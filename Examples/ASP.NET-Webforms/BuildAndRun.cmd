rem @echo off

if %PROCESSOR_ARCHITECTURE%==x86 (
            set MSBuild="%ProgramFiles%\MSBuild\14.0\Bin\MSBuild.exe"
) else (    set MSBuild="%ProgramFiles(x86)%\MSBuild\14.0\Bin\MSBuild.exe"
)

%MSBuild% Application.sln

"%ProgramFiles(x86)%\IIS Express\iisexpress" /path:%~dp0 /systray:false /clr:v4.0 /port:8080 /trace:error
