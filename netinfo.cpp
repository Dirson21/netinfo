#include "netinfo.h"



NetInfo::NetInfo()
{

}


void NetInfo::getProtConnect(string path_procnet)
{
    string type;
    if (path_procnet == _PATH_PROCNET_TCP)//определение типа протокола
    {
        type = "TCP";
    }
    else if (path_procnet == _PATH_PROCNET_UDP)
    {
        type = "UDP";
    }
    else if (path_procnet == _PATH_PROCNET_TCP6)
    {
        type = "TCP6";
    }
    else if (path_procnet == _PATH_PROCNET_UDP6)
    {
        type = "UDP6";
    }
    else if (path_procnet == _PATH_PROCNET_RAW)
    {
        type = "RAW";
    }
    else
    {
        type = "???";
    }


    if (type.find("6") == string::npos)//если используется ipv4
    {
        //вывод шапки таблицы
        wcout << setw(5) << L"№"  <<setw(5) << L"Тип" << setw(23) <<L"Локальный адрес"
              << setw(23)<< L"Внешний адрес" <<setw(14) << L"Статус"
              << setw(17) << L"Id пользователя"<< setw(22)
              << L"PID/Приложение\n";
    }
    else
    {
        //вывод шапки таблицы
        wcout << setw(5) << L"№"  <<setw(5) << L"Тип" << setw(54) <<L"Локальный адрес"
              << setw(45)<< L"Внешний адрес" <<setw(14) << L"Статус"
              << setw(17) << L"Id пользователя"<< setw(22)
              << L"PID/Приложение\n";
    }

    vector<protocol_info> tcpFile = fileParse(path_procnet);//парсинг файла
    for (int i = 1; i < (int)tcpFile.size(); i++)//цикл по всем соединениям
    {

        auto &tcpOne = tcpFile[i]; //ссылка на текущее соединение
        tcpOne.local_addr = hexToStrIp(tcpOne.local_addr);//перевод аддреса в 10тичный формат
        tcpOne.rem_addr = hexToStrIp(tcpOne.rem_addr);//перевод аддреса в 10тичный формат

        string appPidName = "-";
        if (tcpOne.state == TCP_ESTABLISHED)
        {
            appPidName = getPidName(tcpOne.local_port);//получение PID и имя приложения, использующие данный порт
        }
        if (type.find("6") == string::npos)//если используется ipv4
        {
            //Вывод информации на экран
            wcout  << setw(5) << tcpOne.d << setw(5) <<stringConvert(type) << setw(23) << stringConvert(tcpOne.local_addr) + L":" + to_wstring(tcpOne.local_port)
                   << setw(23) << stringConvert(tcpOne.rem_addr) + L":" + to_wstring(tcpOne.rem_port)
                   << setw(14) << TCP_STATES[tcpOne.state]
                   << setw(17)<< tcpOne.uid;
            wcout << setw(22) << stringConvert(appPidName);
            wcout << "\n";
        }
        else
        {
            wcout  << setw(5) << tcpOne.d << setw(5) <<stringConvert(type) << setw(54) << stringConvert(tcpOne.local_addr) + L":" + to_wstring(tcpOne.local_port)
                   << setw(45) << stringConvert(tcpOne.rem_addr) + L":" + to_wstring(tcpOne.rem_port)
                   << setw(14) << TCP_STATES[tcpOne.state]
                   << setw(17)<< tcpOne.uid;
            wcout << setw(22) << stringConvert(appPidName);
            wcout << "\n";
        }



    }
    return;

}

vector<protocol_info> NetInfo::fileParse(string filename)
{

    vector<protocol_info> fileResult;
    ifstream file;

    char rem_addr[128], local_addr[128];

    file.open(filename);//открытие файла
    if (!file.is_open())
        return fileResult;

    while (true)//цикл чтения файла
    {
        string line;
        protocol_info pr;


        getline(file, line, '\n');//Чтение строки
        if (file.eof()) break;
        int num = sscanf(line.c_str(), //Парсинг строки и заполнение информации в структуру
                         "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                         &pr.d, local_addr, &pr.local_port, rem_addr, &pr.rem_port, &pr.state,
                         &pr.txq, &pr.rxq, &pr.timer_run, &pr.time_len, &pr.retr, &pr.uid, &pr.timeout, &pr.inode);

        pr.local_addr = local_addr;
        pr.rem_addr = rem_addr;

        fileResult.push_back(pr);//Добавление информации в общий массив
    }
    file.close();
    return fileResult;

}

vector<string> NetInfo::strtokResult(string buf, string sep)
{
    vector<string> result;

    char* temp;//Разделение строки по разделителю
    temp = strtok((char*)buf.c_str(), sep.c_str());
    while (temp)
    {
        result.push_back(temp);
        temp = strtok(NULL, sep.c_str());
    }
    return result;
}

string NetInfo::hexToStrIp(string hexip)
{
    string result = "";

    string ip = hexip;

    for (int i = ip.size(); i > 0; i-=2) //цикл преобразования в 10ую систему
    {
        string decNum =  to_string(strtol(ip.substr(i-2, 2).c_str(), 0, 16));//перевод из 16-ую в 10-ую систему
        result += decNum;
        if (i - 2 != 0)
        {
            result += ".";
        }
    }
    return result;//возвращение результата

}

wstring NetInfo::stringConvert(string str)//перевод строку широких символов для вывода на экран
{
    return wstring(str.begin(), str.end());
}

string NetInfo::getPidName(int port)
{
    string command;

    int pid = -1;
    string appname = "-";

    command = "lsof -i :" + to_string(port);
    char buf[128];
    FILE *f = popen(command.c_str(), "r");//получение вывода из утилиты lsof
    if (f)
    {
        memset(buf, 0, sizeof (buf));
        fgets(buf, 128, f);
        fgets(buf, 128, f);//чтение из вывода в буффер
        if (strlen(buf))
        {
            sscanf(buf, "%*s %d", &pid);//получение PID из строки
            appname = to_string(pid);
        }
        pclose(f);

    }


    if (pid >= 0)//если PID найден
    {
        command = "/proc/" + to_string(pid) + "/cmdline";
        if ((f = fopen(command.c_str(), "r")))//открытие файла с названием приложения
        {
             memset(buf, 0, sizeof (buf));
             fgets(buf, 128, f);//чтение в в буффер

             vector <string> path = strtokResult(string(buf), "/");//Получение названия приложения
             appname += "/" + strtokResult(path[path.size()-1], " \0")[0];//Объединение PID и приложения
        }
    }
    return appname;
}

