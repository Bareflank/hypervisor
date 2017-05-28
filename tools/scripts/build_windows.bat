@echo off

cd /D C:\ewdk\
call LaunchBuildEnv.cmd

cd /D %1
msbuild /p:Configuration=Debug /p:Platform=x64 /p:TargetVersion=%3 /p:OutDir=%2\outdir\ /p:IntDir=%2\intdir\ Makefile.sln
