# Minecraft RCON Daemon

The daemon is to help for scripting the Minecraft server. It's written by C, to achieve high performance, low costing, and efficient server control.

## Usage

First, you need to enable RCON for your Minecraft server by editing `server.properites`, then you need to run the program in daemon mode. As the daemon, it connects the Minecraft server's RCON port, and then it's ready for you to run commands through it's client mode.

Typically use a screen for the container to run it as the daemon. For example:

    # screen -S MCRCOND ./mcrcond -s
    
If the screen terminates immediately, you can check the log file for the information.

For first run, it will generate a default configuration file as the template, and then exit. You can verify the configuration file for your case.

When the daemon is ready, you can then use the program as the client to run Minecraft commands. The client mode program sends the command to the daemon, and wait for the response from the server, and output it to `stdout`. For example:

    # ./mcrcond -e list
    
If the command needs parameters, use quotation marks:

    # ./mcrcond -e "say Hahaha!"

## Installation

There's no standard way for you to install this software. You need to setup your own script for the daemon to run, and edit the configuration file for your server.

## Notice

Currently, run it as a screen session is recommended because the real daemon mode implementation **isn't stable** . If you can fix this or you think it's needed to run as a real daemon, please modify the code yourself.

If the Minecraft server closes the RCON connection, the daemon mode program exits. **You have to design a loop script** to keep the daemon running. There's mainly 2 reasons that the server will close the connection:

* The RCON client sent a command that's too long (above 14xx bytes)
* The Minecraft server stops

The loop script can be designed like this:

    #!/bin/bash
    while true
    do
     ./mcrcond -s
     sleep 1s
    done

Pay attention to the log file. You can modify the configuration file to select which information you want to log. And the log file would not be automatically separated, so as time goes by, it will grows very very big. You need to remove the old log file to make sure your disk space isn't wasted, but still, the log file may contains very important history informations, please use the log file properly.