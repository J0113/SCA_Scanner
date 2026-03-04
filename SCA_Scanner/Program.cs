using SCA_Scanner;
using System.IO;
using System.Security.Principal;

//change to your path
FileInfo myFilePath = new FileInfo(
    @"C:\Workspace\csharp_codes\SCA_Scanner\SCA_Scanner\myymlfiles\cis_win10_enterprise.yml"
);

string? arg = args.FirstOrDefault(a => !a.StartsWith('-'));

FileInfo file = !string.IsNullOrWhiteSpace(arg)
    ? new FileInfo(arg)
    : myFilePath;

if (!file.Exists)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"File not found: {file.FullName}");
    Console.ResetColor();
    Environment.ExitCode = 2;
    return;
}

SCAFileRunner.RunFile(file.FullName);