#ifndef RSA_H
#define RSA_H

#include <iostream>
#include <cstdint>
#include <random>
#include <functional>
#include <cmath>

#ifdef _MSC_VER
#include <windows.h>
#undef max
#pragma comment(lib, "advapi32.lib")
#elif defined(__GNUC__)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace Crypto
{
    class RSA
    {
    private:
        uint32_t n;
        uint32_t e;
        uint32_t d;
#ifdef _MSC_VER
        HCRYPTPROV hProv;
#endif

    public:
        RSA();
        ~RSA();

        uint32_t get_n() const;
        uint32_t get_e() const;

        uint32_t decrypt(uint32_t) const;
        static uint32_t encrypt(uint32_t, uint32_t, uint32_t);

    private:
        uint32_t seed();
    };

    uint32_t mod_exp(uint32_t, uint32_t, uint32_t);
    void ext_euclid(uint32_t, uint32_t, int32_t&, int32_t&);
    bool is_prime(uint32_t);
}

#endif
