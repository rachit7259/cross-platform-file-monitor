# Cross-Platform File Monitoring API
This is a cross-platform file monitoring service API for a DLP agent.</br>

It's multi-threaded program which provides:
  * File Monitoring - platform-specific APIs for file monitoring.
    * Linux: Uses <code>inotify</code>
    * Windows: Uses <code>ReadDirectoryChangesW</code>
    
  * Content Scanning - Sensitive Data Patterns are defined using regular expressions(regex)

  * API Framework
    * <code>cpp-httplib</code>:  
        The REST API library, cpp-httplib, is header-only and cross-platform.  
        It works with any C++17-compliant compiler on Linux, Windows, and macOS.

The program has the following capabilities:
  * Logging
  * Asynchronus File Scanning
  * RESTful APIs - tested using <code>curl</code>
    * <code>GET /status</code> - Check agent health.
    * <code>POST /enqueue</code> - Enqueue File for scanning.
    * <code>GET /results</code> - Get the scan report(s).
    * <code>GET /logs</code> - display the logs.
    * <code>POST /clear_logs</code> - clears the log file.

 
 The code uses the C++ standard library (<fstream>, <thread>, etc.), which is portable across platforms.

* Compilation Example
    * Linux:
        <pre>g++ -std=c++17 -o dlp_agent dlp_agent.cpp -pthread</pre>
    * Windows:
      * For MinGW:
        <pre>g++ -std=c++17 -o dlp_agent dlp_agent.cpp</pre>

      * For Visual Studio:
        * Use the Visual Studio IDE to create a new project.
        * Add the dlp_agent.cpp file and compile.

 
