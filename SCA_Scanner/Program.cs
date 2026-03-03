using SCA_Scanner;



var path = "C:\\Users\\Jolle\\Downloads\\cis_win10_enterprise.yml";


if (args.Length > 0 && File.Exists(args[0]))
{
    // Mode 1: run a full SCA YAML file
    SCAFileRunner.RunFile(args[0]);
}
else
{
    SCAFileRunner.RunFile(path);
}
