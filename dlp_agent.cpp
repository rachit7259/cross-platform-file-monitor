#include <iostream>
#include <thread>
#include <fstream>
#include <sstream>
#include "cpp-httplib/httplib.h"
#include <sys/inotify.h>
#include <unordered_map>

using namespace std;

//Config
const int BUFFER_SIZE = 1024 * (sizeof(struct inotify_event) + 16);
const string MONITOR_PATH = "./monitor";

//DLP logic: mock scanning for snesitive data
bool scanFileForSensitiveData(const string &filePath)
{
    ifstream file(filePath);

    if(!file.is_open())
    {
        cerr << "Failed to open file: " << filePath <<endl;
        return false;
    }

    string line;
    
    while(getline(file, line))
    {
        if(line.find("password") != string::npos)
        {
            return true; //Detected sensitive content
        }
    }

    return false; //No sensitive content
}

//File monitoring function
void monitorFiles()
{
    int fd = inotify_init();

    if (fd < 0)
    {
        cerr << "Failed to initialize notify" << endl;
        return;
    }

    int wd = inotify_add_watch(fd, MONITOR_PATH.c_str(), IN_CREATE | IN_MODIFY);

    if(wd < 0)
    {
        cerr << "Failed to add watch on" << MONITOR_PATH << endl;
        return;
    }

    char buffer[BUFFER_SIZE];

    while (true)
    {
        int length = read(fd, buffer, BUFFER_SIZE);

        if(length < 0)
        {
            cerr << "Error reading inotify events" << endl;
            break;
        }

        int i = 0;

        while (i < length)
        {
            struct inotify_event *event = (struct inotify_event*) &buffer[i];

            if (event->len)
            {
                string filePath = MONITOR_PATH + "/" + event->name;

                if (event->mask & IN_CREATE || event->mask & IN_MODIFY)
                {
                    cout << "FIle event detected: " << filePath << endl;

                    if(scanFileForSensitiveData(filePath))
                    {
                        cout << "Sensitive content detected in: " << filePath << endl;
                    }
                }
            }

            i+= sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

void startApiServer()
{
    httplib::Server svr;

    svr.Get("/status", [](const httplib::Request&, httplib::Response& res){
        res.set_content("DLP Endpoint Agent is ruinning.", "text/plain");
    });

    svr.Post("/scan", [](const httplib::Request& req, httplib::Response& res) {
        string filePath = req.body; //Assuming body contains the file path

        if(scanFileForSensitiveData(filePath))
        {
            res.set_content("Sensitive content detected.", "text/plain");
        }
        else
        {
            res.set_content("No sensitive content found.", "text/plain");
        }
    });

    cout << "Starting API server on port 8080..." << endl;
    svr.listen("0.0.0.0", 8080);
}

int main()
{
    thread monitorThread(monitorFiles);

    startApiServer();

    monitorThread.join();

    return 0;
}