# ssh_sync_projects

## Need packages:
1. Paramiko

        pip install paramiko

2.  Wathdog

        pip install wathdog

## Sample Config File:

        {
                "monitor_dir":"C:\\kek\\kek\\ssh_test",
                "server_linux":"127.0.0.1",
                "port_linux":"5555",
                "user_linux":"shrek",
                "password_linux":"qwerty",
                "sync_linux_dir":"/home/lol/ssh_test",
                "server_windows":"127.0.0.1",
                "port_windows":"6666",
                "user_windows":"shrek",
                "password_windows":"qwerty",
                "sync_windows_dir":"C:\\ssh_test"
        }


