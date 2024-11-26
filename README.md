# Cross-Platform File Monitoring API
This is a cross-platform file monitoring service API for a DLP agent.</br>
Cross-Platform Compatibility  
  
    Panoptes:  
        Panoptes abstracts platform-specific APIs for file monitoring:  
            Linux: Uses inotify.  
            Windows: Uses ReadDirectoryChangesW.  
            macOS: Uses FSEvents.  
        By relying on Panoptes, the file monitoring logic is inherently cross-platform.  

    cpp-httplib:  
        The REST API library, cpp-httplib, is header-only and cross-platform.  
        It works with any C++17-compliant compiler on Linux, Windows, and macOS.  

    Standard C++ Libraries:  
        The code uses the C++ standard library (<fstream>, <thread>, etc.), which is portable across platforms.  
