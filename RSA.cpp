#include "RSA.h"

namespace Crypto
{
    RSA::RSA()
    {
#ifdef _MSC_VER
        hProvider = 0;
        if (!CryptAcquireContextW(&hProv, 0, 0, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        {
            std::cerr << "Connot acquire cryptographic context." << std::endl;
            ExitProcess(-1);
        }
#endif

        std::default_random_engine generator(seed());
        std::uniform_int_distribution<uint32_t> distribution(0xF000, 0xFFFF);
        auto rand = std::bind(distribution, generator);
        uint32_t p, q, t;
        int32_t x, y;

        do p = static_cast<uint32_t>(rand()) | 1;
        while (!is_prime(p));

        do q = static_cast<uint32_t>(rand()) | 1;
        while (!is_prime(q));

        n = p * q;
        e = 65537;
        t = (p - 1) * (q - 1);

        ext_euclid(65537, t, x, y);

        d = x > 0 ? x : x + t;
    }

    RSA::~RSA()
    {
        n = 0;
        e = 0;
        d = 0;

#ifdef _MSC_VER
        if (!CryptReleaseContext(hProv, 0))
        {
            std::cerr << "Connot release cryptographic context." << std::endl;
            ExitProcess(-1);
        }
#endif
    }

    uint32_t RSA::get_n() const
    {
        return n;
    }

    uint32_t RSA::get_e() const
    {
        return e;
    }

    uint32_t RSA::decrypt(uint32_t c) const
    {
        return mod_exp(c, d, n);
    }

    uint32_t RSA::encrypt(uint32_t m, uint32_t n, uint32_t e)
    {
        return mod_exp(m, e, n);
    }

    uint32_t mod_exp(uint32_t b, uint32_t e, uint32_t m)
    {
        uint64_t c = 1, b_ = b;

        while (e > 0)
        {
            if (e & 1)
                c = (b_ * c) % m;

            e >>= 1;
            b_ = (b_ * b_) % m;
        }

        return static_cast<uint32_t>(c);
    }

    void ext_euclid(uint32_t m, uint32_t n, int32_t& x, int32_t& y)
    {
        int32_t x_, y_;

        if (!(n % m))
        {
            x = 1;
            y = 0;
        }
        else
        {
            ext_euclid(n % m, m, x_, y_);
            x = y_ - (x_ * (n / m));
            y = x_;
        }
    }

    bool is_prime(uint32_t n)
    {
        auto max = static_cast<uint32_t>(floor(sqrt(n))) | 1;

        for (register auto i = max; i >= 3; i -= 2)
        if (n % i == 0)
            return false;

        return true;
    }

    uint32_t RSA::seed()
    {
#ifdef _MSC_VER
        uint8_t* val;
        if (!CryptGenRandom(hProv, 1, val))
        {
            CryptReleaseContext(hProv, 0);
            std::cerr << "Connot get random value." << std::endl;
            ExitProcess(-1);
        }
        return static_cast<uint32_t>(*val);

#elif defined(__GNUC__)
        auto data = open("/dev/random", O_RDONLY);
        uint32_t val;
        size_t len = 0;
        while (len < sizeof val)
        {
            ssize_t res = read(data, ((uint8_t*)&val) + len, (sizeof val) - len);
            if (res < 0)
            {
                std::cerr << "Connot get random value." << std::endl;
                exit(-1);
            }
            len += res;
        }
        close(data);
        return val;

#else
        static uint32_t c;
        if (c++ == 0)
            srand(time(NULL));
        return static_cast<uint32_t>(rand());

#endif
    }
}
