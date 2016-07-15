@echo off

cd C:\ewdk\
call LaunchBuildEnv.cmd

cd %1
msbuild /p:configuration=Release /p:platform=x64 /p:OutDir=%2\outdir\ /p:IntDir=%2\intdir\ Makefile.sln
