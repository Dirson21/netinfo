#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <locale>

#include "netinfo.h"
#include "const_path.h"
using namespace std;

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");

    NetInfo netinfo;

    if (argc > 1)//если есть аргемнты коммандной строки
    {
        //вывод информации в зависимости от аргумента
        if (!strcmp(argv[1], "-t"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_TCP);
        }
        else if (!strcmp(argv[1], "-u"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_UDP);
        }
        else if (!strcmp(argv[1], "-t6"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_TCP6);
        }
        else if (!strcmp(argv[1], "-u6"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_UDP6);
        }
        else if (!strcmp(argv[1], "-r"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_RAW);
        }
        else if (!strcmp(argv[1], "-r6"))
        {
            netinfo.getProtConnect(_PATH_PROCNET_RAW6);
        }
        else
        {
            wcout << L"Доступные комманды:\n";
            wcout << argv[0] << L" -?" << L" Доступные комманды\n";
            wcout << argv[0] << L" -t" << L" Вывод TCP соединений\n";
            wcout << argv[0] << L" -t6" << L" Вывод TCP6 соединений" << endl;
            wcout << argv[0] << L" -u" << L" Вывод UDP соединений" << endl;
            wcout << argv[0] << L" -u6" << L" Вывод UDP6 соединений" << endl;
            wcout << argv[0] << L" -r" << L" Вывод RAW соединений" << endl;
            wcout << argv[0] << L" -r6" << L" Вывод RAW6 соединений" << endl;
        }
        return 0;
    }

    wcout << L"Доступные комманды:\n";
    wcout << argv[0] << L" -?" << L" Доступные комманды\n";
    wcout << argv[0] << L" -t" << L" Вывод TCP соединений\n";
    wcout << argv[0] << L" -t6" << L" Вывод TCP6 соединений" << endl;
    wcout << argv[0] << L" -u" << L" Вывод UDP соединений" << endl;
    wcout << argv[0] << L" -u6" << L" Вывод UDP6 соединений" << endl;
    wcout << argv[0] << L" -r" << L" Вывод RAW соединений" << endl;
    wcout << argv[0] << L" -r6" << L" Вывод RAW6 соединений" << endl;
    return 0;
}
