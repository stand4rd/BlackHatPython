#Requires Win32 Python Extensions
import os
import servicemanager
import shutil
import subprocess
import sys
import win32api
import win32event
import win32service
import win32serviceutil


class VulnService(win32serviceutil.ServiceFramework):


    _svc_name_ = "VulnService"
    _svc_display_name_ = "Vulnerable Service"
    _svc_description_ = ("Executes VBScripts and BAT files at regular intervals." +
                        "What could possibly go wrong?")

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.counter = 0

        self.dos_script = """
        @echo off
        prompt $

        echo -------------------------------------------------------------------------------
        echo Running Processes:
        tasklist

        echo -------------------------------------------------------------------------------
        netstat -oa

        echo -------------------------------------------------------------------------------
        echo Available Hosts:
        net view

        echo -------------------------------------------------------------------------------
        echo Admin Users:
        net localgroup administrators
        exit
        """

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, 'Service is starting'))
        self.timeout = 1000 * 60
        while True:
            ret_code = win32event.WaitForSingleObject(self.hWaitStop, self.timeout)
            if ret_code == win32event.WAIT_OBJECT_0:
                servicemanager.LogInfoMsg("Service is stopping")
                break
            else:
                self.counter += 1
                log_output = "VulnService - %d loops and counting\n\n" % self.counter
                log_output += self.vbs_task() + "\n\n"
                log_output += self.dos_task()
                servicemanager.LogInfoMsg(log_output)

    def vbs_task(self):
        script_name = "vulnservice_task.vbs"
        script_srcpath = "%s\\%s" % (os.path.dirname(sys.argv[0]), script_name)
        script_dstpath = "%s\\%s" % (os.environ['TEMP'], script_name)
        shutil.copyfile(script_srcpath, script_dstpath)
        output = subprocess.check_output("wscript.exe %s" % script_dstpath, shell=False, stderr=subprocess.STDOUT)
        os.unlink(script_dstpath)
        return output

    def dos_task(self):
        script_dstpath = "C:\\TEMP\\vulnservice_task.bat"
        with open (script_dstpath, "w") as bat_file:
            bat_file.write(self.dos_script)
        output = subprocess.check_output("cmd.exe /k %s" % script_dstpath, shell=False, stderr=subprocess.STDOUT)
        os.unlink(script_dstpath)
        return output


def ctrlHandler(ctrlType):
    return True
if __name__ == '__main__':
    win32api.SetConsoleCtrlHandler(ctrlHandler, True)
    win32serviceutil.HandleCommandLine(VulnService)
