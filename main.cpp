#include <iostream>
#include <limits>
#include <cstdint>
#include "RSA.h"

int main()
{
    Crypto::RSA rsa;
    char redo = 0, r = '\n';
    uint32_t n, e, m, c, d, k, t, t_old;

    std::cout << std::endl << "RSA v1.0.0" << std::endl;
    std::cout << "Copyright (C) 2014 Fabio M. Banfi (fbanfi90@gmail.com)";
    std::cout << std::endl << std::endl;

    do
    {
        if (redo == 'n')
            rsa = Crypto::RSA();

        n = rsa.get_n();
        e = rsa.get_e();

        std::cout << "n: " << n << std::endl;
        std::cout << "e: " << e << std::endl;

        do
        {
            std::cout << "m: ";
            std::cin >> m;

            if (!std::cin.good())
            {
                m = std::numeric_limits<uint32_t>::max();
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), r);
            }
        }
        while (m >= n);

        c = rsa.encrypt(m, n, e);
        d = rsa.decrypt(c);

        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), r);
        std::cout << "c: " << c << std::endl;
        std::cout << "m: " << d << std::endl;

        t_old = t = c, k = 0;
        while (true)
        {
            if ((t = Crypto::mod_exp(t, e, n)) == c)
                break;

            t_old = t;
            k++;
        }

        std::cout << "k: " << k << std::endl;
        std::cout << "m: " << t_old << std::endl << std::endl;

        redo = 0;
        while (redo != 'r' && redo != 'n' && redo != 'q')
        {
            std::cout << "Redo / New / Quit? (r/n/q) ";
            std::cin >> redo;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), r);
        }
        std::cout << std::endl;
    }
    while (redo != 'q');

    return 0;
}