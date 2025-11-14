// Aaron Sparks Secure Remote Password Project
#include <NTL/ZZ.h>
#include <openssl/sha.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;
using namespace NTL;

// Fast Modular Exponentation from earlier lab
ZZ fastModExp(const ZZ &base, const ZZ &exp, const ZZ &mod)
{
    ZZ result(1);
    ZZ b = base % mod;
    ZZ e = exp;

    while (e > 0)
    {
        if (IsOdd(e))
        {
            result = (result * b) % mod;
        }
        b = (b * b) % mod;
        e >>= 1;
    }
    return result;
}

// OpenSSL SHA256 Hashing Function, helper for taking in strings
string SHA256_string(const string &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(
        reinterpret_cast<const unsigned char *>(data.data()),
        data.size(),
        hash);
    return string(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);
}

// Converts big int ZZs to bytes
string ZZ_to_bytes(const ZZ &z)
{
    long n = NumBytes(z);
    string out(n, '\0');
    BytesFromZZ(reinterpret_cast<unsigned char *>(&out[0]), z, n);
    reverse(out.begin(), out.end());
    return out;
}

// Turns bytes into a ZZ big integer
ZZ bytes_to_ZZ(const string &bytes)
{
    string reversed(bytes.rbegin(), bytes.rend());
    ZZ z;
    ZZFromBytes(
        z,
        reinterpret_cast<const unsigned char *>(reversed.data()),
        reversed.size());
    return z;
}

// Turns a hex string into bytes
string hex_to_bytes(const string &hex)
{
    string out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        unsigned int byte = 0;
        string byte_str = hex.substr(i, 2);
        stringstream ss;
        ss << std::hex << byte_str;
        ss >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

// Converts bytes to hex, used at the end for M1 and M2
string bytes_to_hex(const string &s)
{
    static const char *hex = "0123456789abcdef";
    string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s)
    {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

// Main SRP Function
void SRP()
{
    // Parameters
    const ZZ p = conv<ZZ>("233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407");
    const ZZ g = conv<ZZ>("5");
    const ZZ a = conv<ZZ>("178242481119686841455935630651378663445606096820544273990935616459488559458304608272255000338033410250251716476091645740768989383318117795973533054447387265892469478456641084508051892282321107993546453743984970483559277046612393702209200069670735617209891130113602827820733610002917156882577171009379314029661");
    const ZZ B_minus = conv<ZZ>("108061662139683748959222368408570194757000511907610414942800530372405285981970954974052918101228477427517033064354246730319653312432919431032341654042396866299954398379435377556867143243881492259112759796278405571975135172112699599965478764916842964895723377682717084865895098141058408417022708722943740980202");
    const ZZ gA = fastModExp(g, a, p);
    cout << "gA: " << gA << endl;

    // Given password and salt
    const string password = "freyalite";
    const string salt_hex = "c52c6393";

    // Hashed password calculation with 1000 iterations
    const string salt = hex_to_bytes(salt_hex);
    string hashed = salt + password;
    for (int i = 0; i < 1000; ++i)
    {
        hashed = SHA256_string(hashed);
    }
    ZZ x = bytes_to_ZZ(hashed);
    cout << "x = " << x << endl;

    // Calculates the K value from hash of P and G
    string P_bytes = ZZ_to_bytes(p);
    string G_bytes = ZZ_to_bytes(g);
    string hash_k = SHA256_string(P_bytes + G_bytes);
    ZZ k = bytes_to_ZZ(hash_k);
    cout << "k = " << k << endl;

    // Computes public key
    ZZ gxp = fastModExp(g, x, p);
    ZZ test1 = B_minus % p;
    ZZ test2 = k % p;
    ZZ test3 = MulMod(test2, gxp, p);
    ZZ pubkey = SubMod(test1, test3, p);

    cout << "pubkey = " << pubkey << endl;

    // Calculates U
    string gB_bytes = ZZ_to_bytes(pubkey);
    string gA_bytes = ZZ_to_bytes(gA);
    string hash_u = SHA256_string(gA_bytes + gB_bytes);
    ZZ u = bytes_to_ZZ(hash_u);
    cout << "u = " << u << endl;

    // Calculates Shared Key
    ZZ aux = a + (u * x);
    ZZ shared_key = fastModExp(pubkey, aux, p);
    cout << "shared_key = " << shared_key << endl;

    // M1 and M2 computations

    // My NetID
    const string netId = "aspark17";

    // Hash of P and G
    string Hp = SHA256_string(ZZ_to_bytes(p));
    string Hg = SHA256_string(ZZ_to_bytes(g));

    // Hash P and Hash G XOR
    string m1_Xor(SHA256_DIGEST_LENGTH, '\0');
    for (size_t i = 0; i < m1_Xor.size(); ++i)
    {
        m1_Xor[i] = static_cast<char>(Hp[i] ^ Hg[i]);
    }

    // Hash of the NetID
    string hash_Id = SHA256_string(netId);

    // shared_key as bytes
    string shared_bytes = ZZ_to_bytes(shared_key);

    // M1 Input, then it is hashed and printed as hex
    string M1_input = m1_Xor + hash_Id + salt + gA_bytes + gB_bytes + shared_bytes;
    string M1 = SHA256_string(M1_input);
    cout << "M1 = " << bytes_to_hex(M1) << endl;

    // Same process on M2
    string M2_input = gA_bytes + M1 + shared_bytes;
    string M2 = SHA256_string(M2_input);
    cout << "M2 = " << bytes_to_hex(M2) << endl;
}

int main()
{
    SRP();
}
