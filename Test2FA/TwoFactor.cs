using System.Security.Cryptography;

namespace Test2FA;

/// <summary>
///     Time-based One-Time Password
/// </summary>
/// <remarks> Funktionsweise 99% ChatGpt </remarks>
public class TwoFactor
{
    public TwoFactor(string secretKeyBase32)
    {
        SecretKeyBase32 = secretKeyBase32;
    }

    public string SecretKeyBase32 { get; init; }

    public string? Label { get; set; }

    public int TOTP => GetToken();

    private int GetToken()
    {
        // Current time in seconds, divided by the time interval (30 seconds)
        long currentUnixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const long timeInterval = 30;
        long counter = currentUnixTime / timeInterval;

        // Convert the counter value to bytes
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counterBytes);
        }

        // Decode the base32 secret key to bytes
        byte[] secretKeyBytes = Base32Decode(SecretKeyBase32);

        HMACSHA1 hmac = new(secretKeyBytes);

        // Compute the HMAC hash
        byte[] hash = hmac.ComputeHash(counterBytes);

        // Dynamic truncation: Extract 4 bytes from the hash
        int offset = hash[^1] & 0x0F;

        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);

        // Modulo to get a 6-digit TOTP value
        int totp = binary % 1000000;

        return totp;
    }

    private static byte[] Base32Decode(string base32)
    {
        const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        base32 = base32.ToUpperInvariant();
        byte[] buffer = new byte[base32.Length * 5 / 8];
        int bufferLength = 0;
        int bits = 0;
        int bitsCount = 0;

        foreach (char c in base32)
        {
            if (c == '=') break;

            int value = base32Chars.IndexOf(c);

            if (value == -1) throw new ArgumentException("Invalid base32 character: " + c);

            bits = (bits << 5) | value;
            bitsCount += 5;

            if (bitsCount >= 8)
            {
                buffer[bufferLength++] = (byte)(bits >> (bitsCount - 8));
                bitsCount -= 8;
            }
        }

        if (bitsCount > 0)
        {
            buffer[bufferLength++] = (byte)(bits << (8 - bitsCount));
        }

        Array.Resize(ref buffer, bufferLength);
        return buffer;
    }
}
