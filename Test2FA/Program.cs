using Test2FA;


Start:
    TwoFactor TwoFA = new("JBSWY3DPEHPK3PXP");

    string topt = TwoFA.TOTP.ToString().Insert(3, " ");
    Console.WriteLine($"Token: {topt}");

    Console.ReadLine();
    goto Start;

