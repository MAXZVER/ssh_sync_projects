import os
import json
import argparse
import time
import paramiko
import traceback
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from stat import S_ISDIR
from scp import SCPClient


def change_path_to_remote(path_file):
    global monitoring_dir_name
    global sync_dir
    list_path_append = []
    current_basename = os.path.basename(path_file)
    while current_basename != monitoring_dir_name:
        list_path_append.append(current_basename)
        path_file = os.path.dirname(path_file)
        current_basename = os.path.basename(path_file)
    path_to_remote = sync_dir
    for sub_path in reversed(list_path_append):
        path_to_remote = os.path.join(path_to_remote, sub_path)
    return path_to_remote


def not_monitoring_file(path_file):
    global list_not_monitor_file
    for file in list_not_monitor_file:
        if file in path_file:
            return True
    return False


def monitoring_file(path_file):
    global list_monitor_file
    for file in list_monitor_file:
        if file in path_file:
            return True
    return False


def monitor_extension(path_file):
    global list_monitor_extension
    filename, file_extension = os.path.splitext(path_file)
    if file_extension in list_monitor_extension:
        return True
    return False


class MyHandler(PatternMatchingEventHandler):

    @staticmethod
    def remote_edit(event):
        """
        event.event_type
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
        # the file will be processed there
        global ssh_transport
        if event.is_directory:
            if not monitoring_file(event.src_path) or not_monitoring_file(event.src_path) or \
                    event.event_type == "modified":
                return
            if event.event_type == "created":
                path_to_create_dir = change_path_to_remote(event.src_path)
                print("CREATE directory: " + path_to_create_dir)
                try:
                    ssh_transport.mkdir_p(path_to_create_dir)
                except Exception as ex:
                    print("Exception create directory: " + str(ex))
                    traceback.print_exc()
                return
        else:
            if not monitoring_file(event.src_path) or not_monitoring_file(event.src_path) \
                    or not monitor_extension(event.src_path):
                return
        if event.event_type == "deleted":
            path_to_delete = change_path_to_remote(event.src_path)
            print("DELETE : " + path_to_delete)
            try:
                ssh_transport.remote_delete(path_to_delete)
            except Exception as ex:
                print("Exception delete: " + str(ex))
                traceback.print_exc()
            return
        ssh_transport.copy_remote_file(event.src_path)

    def on_any_event(self, event):
        self.remote_edit(event)


class SSHTransport:
    def __init__(self, server, port, user, password):
        self.server = server
        self.port = port
        self.user = user
        self.password = password

        self.client_ssh = None
        self.sftp = None
        self.scp = None

        self.init_ssh_transport()

    def create_ssh_client(self):
        self.client_ssh = paramiko.SSHClient()
        self.client_ssh.load_system_host_keys()
        self.client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client_ssh.connect(self.server, self.port, self.user, self.password)

    def init_ssh_transport(self):
        self.create_ssh_client()
        self.sftp = self.client_ssh.open_sftp()
        self.scp = SCPClient(self.client_ssh.get_transport())

    def check_ssh(self):
        if not self.client_ssh.get_transport().is_active():
            self.init_ssh_transport()

    def copy_remote_file(self, path_file):
        self.check_ssh()
        destination_path = change_path_to_remote(path_file)
        print("SCP file: " + path_file + " to " + destination_path)
        try:
            self.scp.put(path_file, recursive=True, remote_path=destination_path)
        except Exception as ex:
            print("Exception scp: " + str(ex))
            traceback.print_exc()

    def mkdir_p(self, remote_directory):
        self.check_ssh()
        """Change to this directory, recursively making new folders if needed.
            Returns True if any folders were created."""
        if remote_directory == '/':
            # absolute path so change directory to root
            self.sftp.chdir('/')
            return
        if remote_directory == '':
            # top-level relative directory must exist
            return
        try:
            self.sftp.chdir(remote_directory)  # sub-directory exists
        except IOError:
            dir_name = os.path.dirname(remote_directory)
            basename = os.path.basename(remote_directory)
            self.mkdir_p(dir_name)  # make parent directories
            self.sftp.mkdir(basename)  # sub-directory missing, so created it
            return True

    def remote_isdir(self, path):
        self.check_ssh()
        try:
            return S_ISDIR(self.sftp.stat(path).st_mode)
        except IOError:
            return False

    def remote_delete(self, path):
        self.check_ssh()
        files = self.sftp.listdir(path=path)
        for sub_file in files:
            file_path = os.path.join(path, sub_file)
            if self.remote_isdir(file_path):
                self.remote_delete(file_path)
            else:
                self.sftp.remove(file_path)

    def close_ssh_transport(self):
        try:
            self.sftp.close()
            self.scp.close()
            self.client_ssh.close()
        except Exception as ex:
            print("Exception close ssh transport: " + str(ex))
            traceback.print_exc()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Tool to sniff traffic")
    parser.add_argument("-c", "--config-file", dest="config_file",
                        help="", required=True)
    # parser.add_argument( "-s", "--sever-name", dest="linux_dir",
    #                     help="", required=True)
    # parser.add_argument("-w", "--windows-dir", dest="win_dit",
    #                     help="", required=True)
    args = parser.parse_args()

    list_monitor_file = []
    list_monitor_extension = []
    list_not_monitor_file = []

    f = open(args.config_file, "rb")
    config_options = json.load(f)
    f.close()
    if "monitor_dir" not in config_options:
        print("Need monitor directory")
        exit(1)
    elif not os.path.isdir(config_options["monitor_dir"]):
        print(str(config_options["monitor_dir"]) + " is not a directiry")
        exit(1)
    if "server_linux" not in config_options:
        print("Need server_linux linux for ssh")
        exit(1)
    if "port_linux" not in config_options:
        print("Need port linux for ssh")
        exit(1)
    if "user_linux" not in config_options:
        print("Need user linux for ssh")
        exit(1)
    if "password_linux" not in config_options:
        print("Need password linux for ssh")
        exit(1)
    if "linux_dir" not in config_options:
        print("Need sync directory linux for ssh")
        exit(1)
    if "list_monitor_file" in config_options:
        list_monitor_file = config_options["list_monitor_file"]
    if "list_not_monitor_file" in config_options:
        list_not_monitor_file = config_options["list_not_monitor_file"]
    if "list_monitor_extension" in config_options:
        list_monitor_extension = config_options["list_monitor_extension"]

    monitoring_dir_name = os.path.basename(config_options["monitor_dir"])
    sync_dir = config_options["linux_dir"]

    ssh_transport = SSHTransport(config_options["server_linux"], int(config_options["port_linux"]),
                                 config_options["user_linux"], config_options["password_linux"])

    observer = Observer()
    observer.schedule(MyHandler(), path=config_options["monitor_dir"], recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    # Close to end
    ssh_transport.close_ssh_transport()
    observer.join()
