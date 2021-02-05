# The Minecraft RCON Daemon

The daemon is to help for scripting the Minecraft server. It's written by C, to achieve high performance, low costing, and efficient per-command responsible server control.

## Usage

First, you need to enable RCON for your Minecraft server by editing `server.properites` to enable the RCON port of the server. Then you can run the program as a daemon, it connects the Minecraft server's RCON port, and then it's ready for you to run commands through it's client mode.

Typically run the daemon by a single command line:

    # ./mcrcond -s

If you want to stop the daemon, use `kill` or `killall` to stop it:

    # killall mcrcond

Or you can also use a screen for the container to run it as the daemon. For example:

    # screen -S MCRCOND ./mcrcond -s
    
If the screen terminates immediately, you can check the log file for the information. For the first run, it will generate a default configuration file as the template. You can edit the configuration file to make it suitable for your server, then restart the daemon.

When the daemon is ready, you can then run the program as the client to send Minecraft commands to the server. The client mode program sends the command to the daemon, and the daemon sends the command to the server. After receiving the responses from the server, the daemon returns them to the client, then the client shows the output through `stdout`. For example:

    # ./mcrcond -e list

Then you can see the player lists. The standard output can be redirected to files or pipes.

If the command needs parameters, you have to use the quotation marks:

    # ./mcrcond -e "say Hahaha!"

## Installation

There's no standard way for you to install this software. You need to setup your own script for the daemon to run, and edit the configuration file for your server.

To compile this program, simply run `make`. The source code is a single `.c` file, use `gcc` or `clang` is able to compile it to get the executable.

## Notice

If the daemon is running as a screen session, and the Minecraft server closes the RCON connection, the program exits. **You have to design a loop script** to keep the daemon running when using `-s` option to run. There's mainly 2 reasons that the server will close the connection:

* The RCON client sent a command that's too long (above 14xx bytes)
* The Minecraft server stops

The loop script can be designed like this:

    #!/bin/bash
    while true
    do
     ./mcrcond -s
     sleep 1s
    done

And the script file (assume the name is `mcrcond_loop.sh`) should be run as:

    screen -S MCRCOND ./mcrcond_loop.sh

Pay attention to the log file. You can modify the configuration file to select which information you want to log. And the log file would not be automatically separated, so as time goes by, it will grows very very big. You need to remove the old log file to make sure your disk space isn't wasted, but still, the log file may contains very important history informations, please use the log file properly.
