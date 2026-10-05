using KiwiCaptcha;

if (args.Contains("--help") || args.Contains("-h"))
{
    Console.WriteLine(
        "usage: kiwicaptcha-doctor --secret SECRET [--store memory://|redis://host:port] " +
        "[--scopes a,b] [--profile standard|argon16|argon32|argon64]");
    return 0;
}

string secret = "";
string storeUrl = "memory://";
string scopesFlag = "";
string profile = "standard";
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--secret":
            secret = Next(args, ref i);
            break;
        case "--store":
            storeUrl = Next(args, ref i);
            break;
        case "--scopes":
            scopesFlag = Next(args, ref i);
            break;
        case "--profile":
            profile = Next(args, ref i);
            break;
        default:
            Console.Error.WriteLine("kiwicaptcha-doctor: unknown flag " + args[i]);
            return 2;
    }
}

var scopes = scopesFlag.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
var results = Doctor.Run(secret, storeUrl, scopes, profile);
var failed = false;
foreach (var result in results)
{
    Console.WriteLine($"{(result.Ok ? "ok  " : "FAIL")} {result.Name}: {result.Detail}");
    failed |= !result.Ok;
}
if (failed)
{
    Console.WriteLine("doctor: the deployment needs attention");
    return 1;
}
Console.WriteLine("doctor: every check passed");
return 0;

static string Next(string[] args, ref int index)
{
    index++;
    if (index >= args.Length)
    {
        Console.Error.WriteLine("kiwicaptcha-doctor: missing value after " + args[index - 1]);
        Environment.Exit(2);
    }
    return args[index];
}
