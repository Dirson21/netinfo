#ifndef NETINFO_H
#define NETINFO_H
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <map>

#include "const_path.h"

using namespace std;

//Константы состояний
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NEW_SYN_RECV,

    TCP_MAX_STATES
};

//структура, где храниться информация о протоколе
struct protocol_info
{
        unsigned long rxq, txq, time_len, retr, inode;
        int num, local_port, rem_port, d, state, uid, timer_run, timeout, pid;
        string rem_addr, local_addr, timers, appname;
};


// Основной класс
class NetInfo
{
public:
    NetInfo();
    void getProtConnect(string path_procnet);//поиск и вывод информации на экран

private:
    vector<protocol_info> fileParse(string filename);//Парсинг файлов
    vector<string> strtokResult(string buf,string sep);//Разделение строки по разделителю
    string hexToStrIp(string hexip);//конвертирование IP-адреса из 16-го формата в 10-ый
    wstring stringConvert(string str);//конвентирование в строку широких символов
    string getPidName(int port);//Получение информации о PID процесса, который прослушивает порт

    vector<wstring> TCP_STATES//Список состояний протокола
    {
        L"",
        L"ESTABLISHED",
        L"SYN-SENT",
        L"SYN-RECEIVED",
        L"FIN-WAIT-1",
        L"FIN-WAIT-2",
        L"TIME-WAIT",
        L"CLOSE",
        L"CLOSE_WAIT",
        L"LAST_ACK",
        L"LISTEN",
        L"CLOSING",
        L"NEW_SYN_RECV",
        L"MAX_STATES"
    };
};

#endif // NETINFO_H
