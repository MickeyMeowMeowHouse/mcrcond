///////////////////////////////////////////////////////////////////////////////
//
// The MIT License
//
// Copyright 2021 0xAA55
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
///////////////////////////////////////////////////////////////////////////////

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define EXEC_NAME	"mcrcond"
#define LOCK_FILE	"/tmp/mcrcond.lock"	// PID file name
#define LOG_FILE	"mcrcond.log"		// log file name
#define CFG_FILE	"mcrcond.conf"		// configure file name

#define DEFAULT_DAEMON_HOST "localhost"
#define DEFAULT_DAEMON_PORT 25585
#define DEFAULT_DAEMON_BACKLOG 256

#define RCON_HEADER_SIZE 12
#define MAX_RCON_REQUEST 1500
#define MAX_RCON_RESPONSE_WAIT 3
#define MAX_RCON_RESPONSE_PAYLOAD 4096
#define MAX_RCON_RESPONSE (MAX_RCON_RESPONSE_PAYLOAD + RCON_HEADER_SIZE)
#define CLIENT_BUFFER_SIZE 4096
#define SOCKET_BUFFER_SIZE 8192

static int signal_exit_catch = 0;
static void signal_handler(int sig)
{
	switch(sig)
	{
	case SIGINT:
	case SIGTERM:
		signal_exit_catch = 1;
		break;
	}
}

// The client's structure, managed by the daemon
typedef struct daemon_client_struct
{
	int socket_client;
	int request_id;

	// The client sends the command to execute.
	// Max command length should be limited under 1.5 kb
	// The client sends the length of the command first, then the command.
	// After the whole command received, the daemon pack up the whole thing and send it to rcon, wait for the response.
	char buffer[CLIENT_BUFFER_SIZE];
	size_t buffer_received;
	size_t buffer_to_receive;
	int buffer_sent;

	// The rcon server returns a response, with it's response packet size specified.
	// However, the server may send multiple response packets.
	// The packets are the fragmentation of the output of the command.
	// If a packet size is exactly 4 kb, then it's possible to be fragmented, and it's necessary to poke the server with some invalid packets.
	char response[MAX_RCON_RESPONSE];
	size_t response_size;
	int response_received;
	int response_sent;
	time_t response_time;
}daemon_client_t, *daemon_client_p;

// The daemon's structure
typedef struct daemon_inst_struct
{
	// Parsed configurations
	char conf_rcon_host[256];
	int conf_rcon_port;
	char conf_rcon_auth[64];
	char conf_daemon_listen[256];
	int conf_daemon_port;
	int conf_daemon_backlog;
	int conf_log_rcon;
	int conf_debug;
	int conf_response_newline;

	FILE* fp_log;

	int daemonized;
	int socket_to_rcon;
	int socket_listen;
	int cur_request_id;

	size_t client_count;
	daemon_client_p clients;
}daemon_inst_t, *daemon_inst_p;

// The RCON protocol packet header
typedef struct rcon_packet_struct
{
	int length;
	int request_id;
	int type;
	char payload[0];
}rcon_packet_t, *rcon_packet_p;

static int socket_reuse_addr_port(int sfd)
{
	int value = 1;

	return
		(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof value) >= 0) &
		(setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof value) >= 0);
}

static void di_logtime(daemon_inst_p di, FILE *stream)
{
	time_t t;
	struct tm *tmp;
	char szTime[128];
	t = time(NULL);
	tmp = localtime(&t);
	if (tmp) strftime(szTime, sizeof szTime, "%H:%M:%S", tmp);
	fprintf(stream, "[%s]: ", tmp ? szTime : strerror(errno));
}

void di_printf(daemon_inst_p di, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	di_logtime(di, di->fp_log);
	vfprintf(di->fp_log, format, ap);
	fflush(di->fp_log);
	va_end(ap);
	if (!di->daemonized)
	{
		va_start(ap, format);
		di_logtime(di, stdout);
		vprintf(format, ap);
		va_end(ap);
	}
}

// Delete the daemon instance
void di_delete(daemon_inst_p di)
{
	if(!di) return;
	if(di->socket_to_rcon != -1) close(di->socket_to_rcon);
	if(di->socket_listen != -1) close(di->socket_listen);
	if(di->clients)
	{
		size_t i;
		for (i = 0; i < di->client_count; i++)
		{
			if(di->clients[i].socket_client != -1)
			{
				close(di->clients[i].socket_client);
			}
		}
	}
	if(di->fp_log)
	{
		di_printf(di, "[TERM] The daemon '"EXEC_NAME"' has been terminated.\n");
		fclose(di->fp_log);
	}
	free(di);
}

// Create the daemon instance
daemon_inst_p di_create(char* log_filepath)
{
	daemon_inst_p di = NULL;
	if (!log_filepath) return di;

	di = malloc(sizeof *di);
	if (!di) return di;
	memset(di, 0, sizeof *di);

	di->socket_to_rcon = -1;
	di->socket_listen = -1;

	strcpy(di->conf_rcon_host, "localhost");
	di->conf_rcon_port = 25575;
	strcpy(di->conf_rcon_auth, "EX");
	strcpy(di->conf_daemon_listen, "localhost");
	di->conf_daemon_port = DEFAULT_DAEMON_PORT;
	di->conf_daemon_backlog = DEFAULT_DAEMON_BACKLOG;
	di->conf_log_rcon = 0;

	di->fp_log = fopen(log_filepath, "a");
	if(!di->fp_log)
	{
		// fprintf(stderr, "Open log file '%s' failed: %s.\n", log_filepath, strerror(errno));
		goto FailExit;
	}
	di_printf(di, "[INIT] Starting daemon '"EXEC_NAME"'.\n");

	return di;
FailExit:
	di_delete(di);
	return NULL;
}

// The default configure file generation
int di_write_default_cfg_file(daemon_inst_p di, char *cfg_filepath)
{
	FILE *fp = fopen(cfg_filepath, "w");
	if(!fp)
	{
		di_printf(di, "[FAIL] Writing default configure file '%s' failed: %s.\n", cfg_filepath, strerror(errno));
		return 0;
	}

	di_printf(di, "[FAIL] Generating the default configure file to '%s'.\n", cfg_filepath);
	di_printf(di, "[INFO] Please check the generated configure file and restart the daemon.\n");

	fprintf(fp, "# The minecraft server RCON address, port, password\n");
	fprintf(fp, "rcon-host=%s\n", di->conf_rcon_host);
	fprintf(fp, "rcon-port=%d\n", di->conf_rcon_port);
	fprintf(fp, "rcon-auth=%s\n", di->conf_rcon_auth);
	fprintf(fp, "\n");
	fprintf(fp, "# From what addresses can connect the daemon\n");
	fprintf(fp, "daemon-listen=%s\n", di->conf_daemon_listen);
	fprintf(fp, "\n");
	fprintf(fp, "# The port of the daemon\n");
	fprintf(fp, "daemon-port=%d\n", di->conf_daemon_port);
	fprintf(fp, "\n");
	fprintf(fp, "# How many connections to the daemon at the same time\n");
	fprintf(fp, "daemon-backlog=%d\n", di->conf_daemon_backlog);
	fprintf(fp, "\n");
	fprintf(fp, "# Uncomment next line to log all RCON activities\n");
	fprintf(fp, "#log-rcon=1\n");
	fprintf(fp, "\n");
	fprintf(fp, "# Uncomment next line to add a newline ending to responses\n");
	fprintf(fp, "#response-add-newline=1\n");
	fprintf(fp, "\n");

	fclose(fp);
	return 1;
}

// Parse existing configure file
int di_parse_cfg_file(daemon_inst_p di, char *cfg_filepath)
{
	FILE *fp = fopen(cfg_filepath, "r");
	if(!fp)
	{
		if(errno == ENOENT)
		{
			di_printf(di, "[FAIL] Configure file '%s' not found.\n", cfg_filepath);
			di_write_default_cfg_file(di, cfg_filepath);
			return 0;
		}
		else
		{
			di_printf(di, "[FAIL] Open configure file '%s' failed: %s.\n", cfg_filepath, strerror(errno));
			return 0;
		}
	}
	else
	{
		int line_no = 0;
		int failure = 0;
		char line_buf[512];
		const char token_delims[] = " =\r\n";
		do
		{
			char *ch;

			// Read the configure file line by line, and use 'ch' to parse each line.
			ch = fgets(line_buf, sizeof line_buf, fp); line_no++;
			if(!ch && !feof(fp))
			{
				failure = 1;
				break;
			}

			// Remove the comments
			ch = strchr(line_buf, '#');
			if (ch) *ch = '\0';

			// Ignore the leading space
			ch = line_buf;
			while(isspace(*ch)) ch++;

			// Ignore empty line
			if (*ch == '\r' ||*ch == '\n' || *ch == '\0') continue;

			// Remove the spaces of the line
			memmove(line_buf, ch, strlen(ch) + 1);

			// Parse the line
			ch = strtok(line_buf, token_delims);
			if (!ch)
			{
				failure = 2;
				break;
			}
			if (!strcmp(ch, "rcon-host"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%s", &di->conf_rcon_host[0]) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "rcon-port"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_rcon_port) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "rcon-auth"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%s", &di->conf_rcon_auth[0]) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "daemon-listen"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%s", &di->conf_daemon_listen[0]) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "daemon-port"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_daemon_port) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "daemon-backlog"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_daemon_backlog) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "log-rcon"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_log_rcon) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "debug"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_debug) != 1)
				{
					failure = 2;
					break;
				}
			}
			else if(!strcmp(ch, "response-add-newline"))
			{
				ch = strtok(NULL, token_delims);
				if(!ch || sscanf(ch, "%d", &di->conf_response_newline) != 1)
				{
					failure = 2;
					break;
				}
			}
			else
			{
				failure = 2;
				break;
			}
		}while(!feof(fp));
		fclose(fp);
		switch(failure)
		{
		case 0:
			return 1;
		case 1:
			di_printf(di, "[FAIL] Error occurs while parsing configure file '%s' at line %d:\n", cfg_filepath, line_no);
			di_printf(di, "[FAIL] \t%s.\n", strerror(errno));
			return 0;
		case 2:
			di_printf(di, "[FAIL] Error occurs while parsing configure file '%s' at line %d:\n", cfg_filepath, line_no);
			di_printf(di, "[FAIL] Unknown '%s'.\n", line_buf);
			return 0;
		default:
			di_printf(di, "[FAIL] Error occurs while parsing configure file '%s' at line %d:\n", cfg_filepath, line_no);
			di_printf(di, "[FAIL] Unknown '%s' because of unknown 'failure' %d.\n", line_buf, failure);
			return 0;
		}
	}
}

// Check if 'struct sockaddr' is an IPv4 address
static int is_v4_addr(struct sockaddr *addr, socklen_t addr_len)
{
	return (addr->sa_family == AF_INET && addr_len == sizeof(struct sockaddr_in));
}

// Create the socket for listening from the clients
static int di_init_listener_socket(daemon_inst_p di)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int s, sfd = -1;
	char port_buf[8];
	size_t i;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // Stream socket
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE; // Numeric port and wildcard IP address
	hints.ai_protocol = IPPROTO_TCP; // Only TCP
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	sprintf(port_buf, "%d", di->conf_daemon_port);
	s = getaddrinfo(di->conf_daemon_listen, port_buf, &hints, &result);
	if (s)
	{
		di_printf(di, "[FAIL] Listen address '%s:%s' not resolvable: %s\n", di->conf_daemon_listen, port_buf, gai_strerror(s));
		goto FailExit;
	}
	for(rp = result; rp; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		if (!socket_reuse_addr_port(sfd))
		{
			di_printf(di, "[WARN] Trying to enable reuse of address and port failed: %s.\n", strerror(s));
		}
		if (is_v4_addr(rp->ai_addr, rp->ai_addrlen))
		{
			struct sockaddr_in *v4_addr = (struct sockaddr_in*)rp->ai_addr;
			di_printf(di, "[INFO] Binding to resolved address '%s:%d'\n",
				inet_ntoa(v4_addr->sin_addr),
				ntohs(v4_addr->sin_port));
		}
		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
		{
			di_printf(di, "[INFO] Bind to address '%s:%s' successful\n", di->conf_daemon_listen, port_buf);
			break;
		}
		else if (is_v4_addr(rp->ai_addr, rp->ai_addrlen))
		{
			struct sockaddr_in *v4_addr = (struct sockaddr_in*)rp->ai_addr;
			di_printf(di, "[WARN] Bind to resolved address '%s:%d' failed.\n",
				inet_ntoa(v4_addr->sin_addr),
				ntohs(v4_addr->sin_port));
		}
		close(sfd);
	}
	if (!rp)
	{
		di_printf(di, "[FAIL] None of the resolved address from '%s:%s' cannot be bound.\n", di->conf_daemon_listen, port_buf);
		goto FailExit;
	}
	freeaddrinfo(result); result = NULL;
	di->socket_listen = sfd;

	if(listen(di->socket_listen, di->conf_daemon_backlog) < 0)
	{
		di_printf(di, "[FAIL] Listen to address '%s:%s' with backlog %d failed: %s.\n",
			di->conf_daemon_listen, port_buf, di->conf_daemon_backlog, strerror(errno));
		goto FailExit;
	}
	else
	{
		di_printf(di, "[INFO] Listening to address '%s:%s' with backlog %d\n", di->conf_daemon_listen, port_buf, di->conf_daemon_backlog);
	}

	di->client_count = di->conf_daemon_backlog;
	di->clients = malloc(di->client_count * sizeof di->clients[0]);
	if (!di->clients)
	{
		di_printf(di, "[FAIL] Prepare for incoming %d connections failed: %s.\n",
			(int)di->client_count, strerror(errno));
		goto FailExit;
	}
	memset(di->clients, 0, di->client_count * sizeof di->clients[0]);
	for(i = 0; i < di->client_count; i++)
	{
		di->clients[i].socket_client = -1;
	}

	return 1;
FailExit:
	if(di->socket_listen != -1)
	{
		close(di->socket_listen);
		di->socket_listen = -1;
	}
	if(result) freeaddrinfo(result);
	return 0;
}

// Create the socket for listening from the clients
static int di_init_rcon_socket(daemon_inst_p di)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int s, sfd = -1;
	char port_buf[8];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // Stream socket
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE; // Numeric port and wildcard IP address
	hints.ai_protocol = IPPROTO_TCP; // Only TCP
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	sprintf(port_buf, "%d", di->conf_rcon_port);
	s = getaddrinfo(di->conf_rcon_host, port_buf, &hints, &result);
	if (s)
	{
		di_printf(di, "[FAIL] RCON address '%s:%s' not resolvable: %s\n", di->conf_rcon_host, port_buf, gai_strerror(s));
		goto FailExit;
	}
	for(rp = result; rp; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sfd);
	}
	if (!rp)
	{
		di_printf(di, "[FAIL] Connect to RCON host '%s:%s' failed\n", di->conf_rcon_host, port_buf);
		goto FailExit;
	}
	freeaddrinfo(result); result = NULL;

	di->socket_to_rcon = sfd;
	return 1;
FailExit:
	if(di->socket_to_rcon != -1)
	{
		close(di->socket_to_rcon);
		di->socket_to_rcon = -1;
	}
	if(result) freeaddrinfo(result);
	return 0;
}

static int di_send_rcon_packet(daemon_inst_p di, int request_id, int type, void *packet, size_t size, size_t *ret_send_len)
{
	size_t send_len = RCON_HEADER_SIZE + size + 1;
	char send_buf[SOCKET_BUFFER_SIZE];
	rcon_packet_p packsend = (rcon_packet_p)&send_buf;

	packsend->length = send_len - 4;
	packsend->request_id = request_id;
	packsend->type = type;
	memcpy(packsend->payload, packet, size);
	packsend->payload[size] = '\0';
	*ret_send_len = send_len;
	if (di->conf_log_rcon) di_printf(di, "[RCON] %s\n", packet);
	return send(di->socket_to_rcon, send_buf, send_len, 0);
}

// Start authentication to the RCON server
static int di_rcon_auth(daemon_inst_p di)
{
	char recv_buf[MAX_RCON_RESPONSE];
	int nrecv;
	rcon_packet_p packrecv = (rcon_packet_p)&recv_buf;
	size_t send_len;
	int req_id = di->cur_request_id++;

	if(di_send_rcon_packet(di, req_id, 3, di->conf_rcon_auth, strlen(di->conf_rcon_auth), &send_len) != send_len)
	{
		di_printf(di, "[FAIL] Authentication to RCON host '%s:%d' by password '%s' failed: send()\n", di->conf_rcon_host, di->conf_rcon_port, di->conf_rcon_auth);
		goto FailExit;
	}

	nrecv = recv(di->socket_to_rcon, recv_buf, sizeof recv_buf, 0);
	if(!nrecv)
	{
		di_printf(di, "[FAIL] Authentication to RCON host '%s:%d' by password '%s' failed: Connection reset by the peer.\n", di->conf_rcon_host, di->conf_rcon_port, di->conf_rcon_auth);
		goto FailExit;
	}
	if(nrecv < 0)
	{
		di_printf(di, "[FAIL] Authentication to RCON host '%s:%d' by password '%s' failed: %s\n", di->conf_rcon_host, di->conf_rcon_port, di->conf_rcon_auth, strerror(errno));
		goto FailExit;
	}
	if(packrecv->request_id == req_id)
	{
		di_printf(di, "[AUTH] Authentication to RCON host '%s:%d' by password '%s' succeeded.\n", di->conf_rcon_host, di->conf_rcon_port, di->conf_rcon_auth);
	}
	else
	{
		di_printf(di, "[FAIL] Authentication to RCON host '%s:%d' by password '%s' failed: Wrong password\n", di->conf_rcon_host, di->conf_rcon_port, di->conf_rcon_auth);
		goto FailExit;
	}

	return 1;
FailExit:
	return 0;
}

// Initialize the daemon after the configures were loaded
int di_init(daemon_inst_p di)
{
	di->cur_request_id = (int)time(NULL);

	if(!di_init_rcon_socket(di)) return 0;
	if(!di_rcon_auth(di)) return 0;
	if(!di_init_listener_socket(di)) return 0;

	return 1;
}

// Run the daemon
int di_run(daemon_inst_p di)
{
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout;
	size_t i;
	int retval;
	char recv_buf[SOCKET_BUFFER_SIZE];
	char response_buf[SOCKET_BUFFER_SIZE * 2];
	rcon_packet_p packrecv = (rcon_packet_p)response_buf;
	size_t cb_to_recv = 0;
	size_t cb_recv = 0;

	while(!signal_exit_catch)
	{
		int maxfd = 0;
		int rcon_ready_to_send = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		// Add active client sockets to the select() file descriptors list
		for(i = 0; i < di->client_count; i ++)
		{
			int sock = di->clients[i].socket_client;
			if(sock != -1)
			{
				FD_SET(sock, &readfds);
				FD_SET(sock, &writefds);
				maxfd ++;
			}
		}

		// Add the RCON server to the list
		FD_SET(di->socket_to_rcon, &readfds);
		FD_SET(di->socket_to_rcon, &writefds);
		maxfd ++;

		// Add the listener server to the list
		if(maxfd < di->client_count)
		{
			FD_SET(di->socket_listen, &readfds);
			maxfd ++;
		}

		// First, wait for any activity of the sockets.
		retval = select(FD_SETSIZE, &readfds, &writefds, NULL, &timeout);
		if(retval == -1)
		{
			di_printf(di, "[FAIL] select() failed: %s.\n", strerror(errno));
			return 0;
		}

		// Receive responses from the RCON server
		if (!cb_to_recv || cb_recv < cb_to_recv)
		{
			if (FD_ISSET(di->socket_to_rcon, &readfds))
			{
				retval = recv(di->socket_to_rcon, recv_buf, sizeof recv_buf, 0);
				if (retval <= 0)
				{
					if (retval < 0)
					{
						di_printf(di, "[FAIL] Receive responses from the RCON server failed: %s.\n", strerror(errno));
					}
					else
					{
						// If too many of the requests had sent in a very short time, the server closes the connection.
						di_printf(di, "[INFO] The RCON server closed the connection.\n");
					}
					return 1;
				}
				if (retval + cb_recv > sizeof response_buf)
				{
					// This would hardly happen since 'response_buf' is twice big as 'recv_buf' and 'recv_buf' is 8kb and it's twice big as the maximum response payload size
					di_printf(di, "[FAIL] The RCON server returned a packet with wrong size (%d) which was too big to fit the buffer.\n", (int)(retval + cb_recv));
					return 0;
				}
				memcpy(&response_buf[cb_recv], recv_buf, retval);
				cb_recv += retval;

				if (!cb_to_recv && cb_recv >= 4) cb_to_recv = packrecv->length + 4;
				if (di->conf_debug) di_printf(di, "[DEBUG] RCON response received: packet size = %zu, received size = %zu\n", cb_to_recv, cb_recv);
			}
		}

		// If a complete response had received, redirect it to the specific client
		if(cb_to_recv && cb_recv >= cb_to_recv)
		{
			size_t cb_payload = cb_to_recv - RCON_HEADER_SIZE;
			if (packrecv->type != 0)
			{
				di_printf(di, "[FAIL] The RCON server returned a packet with unknown type (%d).\n", packrecv->type);
				return 0;
			}

			// Redirect the packet to the client which have the same request id
			for(i = 0; i < di->client_count; i++)
			{
				daemon_client_p c = &di->clients[i];

				// Check if activity or not
				if (c->socket_client == -1) continue;

				// Check the request id
				if (c->request_id != packrecv->request_id) continue;

				// Check if it had redirected the response it already got
				if (c->response_received && !c->response_sent) break;

				memcpy(c->response, packrecv->payload, cb_payload);
				c->response_received = 1;
				c->response_sent = 0;
				c->response_size = cb_payload;
				if (di->conf_debug) di_printf(di, "[DEBUG] RCON response copied to %zu: %s\n", i, c->response);
				break;
			}

			// Check if no client matches
			if (i >= di->client_count)
			{
				if (di->conf_log_rcon) di_printf(di, "[RCON] (Not redirected to client) %s\n", packrecv->payload);
				di_printf(di, "[INFO] The RCON server returned a packet with a request id (%d) which doesn't belongs to current clients.\n", packrecv->request_id);
			}
			cb_recv -= cb_to_recv;
			if (cb_recv)
			{
				memmove(response_buf, &response_buf[cb_to_recv], cb_recv);
				if (cb_recv >= 4)
				{
					cb_to_recv = packrecv->length + 4;
					if (di->conf_debug) di_printf(di, "[DEBUG] Remaining %zu bytes of response with packet size %zu to redirect.\n", cb_recv, cb_to_recv);
				}
				else
				{
					cb_to_recv = 0;
					if (di->conf_debug) di_printf(di, "[DEBUG] Remaining %zu bytes of response to redirect.\n", cb_recv);
				}
			}
			else
			{
				cb_to_recv = 0;
			}
		}
		
		if (FD_ISSET(di->socket_to_rcon, &writefds))
		{
			rcon_ready_to_send = 1;
		}

		for(i = 0; i < di->client_count; i++)
		{
			daemon_client_p c = &di->clients[i];
			int sock = c->socket_client;
			if (sock == -1) continue;
			if (!c->buffer_to_receive || c->buffer_received < c->buffer_to_receive)
			{
				if (FD_ISSET(sock, &readfds))
				{
					retval = recv(sock, recv_buf, sizeof recv_buf, 0);
					// Check if error occurs or the client closes the socket
					if (retval <= 0)
					{
						if (retval < 0)
						{
							di_printf(di, "[WARN] Receive requests from client %zu failed: %s.\n", i, strerror(errno));
						}
						else
						{
							if (di->conf_debug) di_printf(di, "[DEBUG] The client %zu closed the connection.\n", i);
						}
						c->socket_client = -1;
						close(sock);
						continue;
					}

					// Copy the received data to the end of the buffer
					if (c->buffer_received + retval <= sizeof c->buffer)
					{
						memcpy(&c->buffer[c->buffer_received], recv_buf, retval);
						c->buffer_received += retval;
					}
					else
					{
						di_printf(di, "[WARN] The client %zu had sent too many data (%zu bytes) that could not fit the buffer (capacity of %zu bytes).\n",
							i, c->buffer_received + retval, sizeof c->buffer);
						c->socket_client = -1;
						close(sock);
						continue;
					}

					// The first 4 bytes is the length of client's packet length.
					if(c->buffer_received >= 4)
					{
						uint32_t packet_size = *(uint32_t*)&c->buffer[0];
						c->buffer_to_receive = packet_size + 4;

						// Check the size, it shouldn't exceed MAX_RCON_REQUEST and shouldn't be zero
						if (packet_size > MAX_RCON_REQUEST || !packet_size)
						{
							di_printf(di, "[WARN] Client %zu sent invalid size of request: '%zu' bytes\n",i , c->buffer_to_receive);
							c->socket_client = -1;
							close(sock);
							continue;
						}
						if (di->conf_debug) di_printf(di, "[DEBUG] Receiving client request %zu of %zu bytes\n", c->buffer_received - 4, c->buffer_to_receive - 4);
					}
				}
			}

			// Send the request to RCON server if not sent
			if (c->buffer_to_receive && c->buffer_received >= c->buffer_to_receive)
			{
				if (!c->buffer_sent)
				{
					if (rcon_ready_to_send)
					{
						size_t send_len;
						retval = di_send_rcon_packet(di, c->request_id, 2, &c->buffer[4], c->buffer_received - 4, &send_len);

						// Check if error occurs or the client closes the socket
						if (retval <= 0)
						{
							if (retval < 0)
							{
								di_printf(di, "[FAIL] Send request to the RCON server failed: %s.\n", strerror(errno));
							}
							else
							{
								di_printf(di, "[INFO] The RCON server closed the connection.\n");
							}
							return 1;
						}
						c->buffer_sent = 1;
						if (di->conf_debug) di_printf(di, "[DEBUG] Position %zu, request sent\n", i);
					}
				}
				else if (c->response_received)
				{
					if (!c->response_sent)
					{
						if (FD_ISSET(sock, &writefds))
						{
							// Send the response back to the client
							if (di->conf_response_newline && c->response_size < sizeof c->response)
							{
								c->response[c->response_size++] = '\n';
							}
							retval = send(sock, c->response, c->response_size, 0);

							// Check if error occurs or the client closes the socket
							if (retval <= 0)
							{
								if (retval < 0)
								{
									di_printf(di, "[WARN] Sending response back to the client %zu failed: %s.\n", i, strerror(errno));
								}
								c->socket_client = -1;
								close(sock);
								continue;
							}
							if (di->conf_log_rcon) di_printf(di, "[RCON] %s\n", c->response);
							if (c->response_size >= MAX_RCON_RESPONSE_PAYLOAD)
							{
								c->response_time = time(NULL);
								c->response_sent = 1;
								c->response_received = 0; // Process the fragmentation
								if (di->conf_debug) di_printf(di, "[DEBUG] Waiting for further response of client %zu.\n", i);
							}
							else
							{
								c->socket_client = -1;
								close(sock);
								if (di->conf_debug) di_printf(di, "[DEBUG] Closed the connection to the client %zu.\n", i);
								continue;
							}
						}
					}
					else
					{
						if (c->response_size < MAX_RCON_RESPONSE_PAYLOAD || time(NULL) - c->response_time >= MAX_RCON_RESPONSE_WAIT)
						{
							c->socket_client = -1;
							close(sock);
							if (di->conf_debug) di_printf(di, "[DEBUG] Closed the connection to the client %zu.\n", i);
							continue;
						}
					}
				}
			}
		}

		// Process incoming connections
		if (FD_ISSET(di->socket_listen, &readfds))
		{
			char addr_buf[256];
			socklen_t addr_len = sizeof addr_buf;
			for(i = 0; i < di->client_count; i++)
			{
				daemon_client_p c = &di->clients[i];
				int sock = c->socket_client;
				if (sock != -1) continue;
				sock = accept(di->socket_listen, (struct sockaddr *)&addr_buf, &addr_len);
				if (sock == -1)
				{
					di_printf(di, "[FAIL] Accept the incoming connection failed: %s.\n", strerror(errno));
				}
				else
				{
					if (di->conf_log_rcon)
					{
						char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
						if (getnameinfo((struct sockaddr *)&addr_buf, addr_len,
							hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
							NI_NUMERICHOST | NI_NUMERICSERV) == 0)
						{
							di_printf(di, "[INFO] Accepted connection from %s:%s as client %zu.\n", hbuf, sbuf, i);
						}
						else
						{
							di_printf(di, "[INFO] Accepted connection from unknown client as %zu.\n", i);
						}
					}

					memset(&di->clients[i], 0, sizeof di->clients[i]);
					c->socket_client = sock;
					c->request_id = di->cur_request_id ++;
				}
				break;
			}
			if (i >= di->client_count)
			{
				di_printf(di, "[WARN] No more room for the new connections from the clients.\n");
			}
		}
	}

	return 1;
}

// Move self to run in background
void daemonize()
{
	// Process one to two
	pid_t process_id = fork();
	if (process_id < 0)
	{
		printf("fork failed!\n");
		exit(1);
	}

	// Parent process suicide
	if (process_id > 0)
	{
		exit(0);
	}

	// Child process go to background
	umask(0);
	if (setsid() < 0) exit(1);

	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);
}

// The test code:
// Sometimes 'select()' function doesn't work as man7 says.
// The test shows that the first parameter 'nfds' should be FD_SETSIZE,
// instead of 'Max file descriptor number plus 1'.
// Tested in Linux, FreeBSD, WSL, mingw-w64 in msys2.
/*
static void test_code()
{
	int sock_listen, retval, sock_accept;
	struct sockaddr_in addr;
	socklen_t addr_size = sizeof addr;
	struct timeval tv;
	fd_set readfds;

	printf("RUNNING TEST CODE\n");
	sock_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	printf("%d\n", sock_listen);
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(25595);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	retval = bind(sock_listen, (struct sockaddr*)&addr, sizeof addr);
	printf("%d\n", retval);
	retval = listen(sock_listen, 256);
	printf("%d\n", retval);
	for(;;)
	{
		FD_ZERO(&readfds);
		FD_SET(sock_listen, &readfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
		printf("%d of %d\n", retval, FD_SETSIZE);
		if (FD_ISSET(sock_listen, &readfds))
		{
			printf("FD_ISSET\n");
			break;
		}
	}
	sock_accept = accept(sock_listen, (struct sockaddr*)&addr, &addr_size);
	if (sock_accept >= 0)
	{
		char buf[8192];
		if (addr_size == sizeof addr && addr.sin_family == AF_INET)
		{
			printf("[%s:%d]\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		}
		retval = recv(sock_accept, buf, sizeof buf, 0);
		printf("%d %s\n", retval, buf);
		sprintf(buf, "HTTP/1.1 200 OK\r\n\r\nawdnawvhasdlghvjaselgh\r\n");
		retval = send(sock_accept, buf, strlen(buf), 0);
		printf("%d\n", retval);
		close(sock_accept);
	}
	close(sock_listen);
	exit(0);
}
*/

// The whole program running as the daemon
void run_as_daemon(char *cfg_filepath, char *log_filepath, int do_daemonize)
{
	daemon_inst_p di = NULL;
	int exit_code = 0;

	// test_code();

	if(do_daemonize) daemonize();

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	di = di_create(log_filepath);
	if(!di)
	{
		if(!do_daemonize) fprintf(stderr, "[FAIL] Creating daemon instance failed.\n");
		exit_code = 2;
		goto CleanupExit;
	}

	di->daemonized = do_daemonize;

	if(!di_parse_cfg_file(di, cfg_filepath))
	{
		exit_code = 1;
		goto CleanupExit;
	}

	if(!di_init(di))
	{
		exit_code = 1;
		goto CleanupExit;
	}

	if(!di_run(di))
	{
		exit_code = 1;
		goto CleanupExit;
	}

	exit_code = 0;
CleanupExit:
	di_delete(di);
	exit(exit_code);
}

// The whole program running as the client of the daemon
void run_as_client(char *daemon_address, int daemon_port, char *exec_command)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int s, sfd = -1;
	char port_buf[8];
	char send_buf[SOCKET_BUFFER_SIZE];
	char recv_buf[SOCKET_BUFFER_SIZE];
	size_t command_len = strlen(exec_command);
	int retval;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // Stream socket
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE; // Numeric port and wildcard IP address
	hints.ai_protocol = IPPROTO_TCP; // Only TCP
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	sprintf(port_buf, "%d", daemon_port);
	s = getaddrinfo(daemon_address, port_buf, &hints, &result);
	if (s)
	{
		fprintf(stderr, "Daemon address '%s:%s' not resolvable: %s\n", daemon_address, port_buf, gai_strerror(s));
		goto FailExit;
	}
	for(rp = result; rp; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sfd);
	}
	if (!rp)
	{
		fprintf(stderr, "Connect to daemon host '%s:%s' failed\n", daemon_address, port_buf);
		goto FailExit;
	}
	freeaddrinfo(result); result = NULL;

	*(uint32_t*)&send_buf[0] = command_len;
	memcpy(&send_buf[4], exec_command, command_len);
	retval = send(sfd, send_buf, command_len + 4, 0);
	if (retval < 0)
	{
		fprintf(stderr, "Send command to daemon host '%s:%s' failed: %s\n", daemon_address, port_buf, strerror(errno));
		goto FailExit;
	}
	if (retval == 0)
	{
		fprintf(stderr, "Daemon host '%s:%s' had reset the connection\n", daemon_address, port_buf);
		goto FailExit;
	}

	for(;;)
	{
		retval = recv(sfd, recv_buf, sizeof recv_buf, 0);
		if (retval == 0)
		{
			break;
		}
		else if (retval < 0)
		{
			fprintf(stderr, "Receive response from host '%s:%s' failed: %s\n", daemon_address, port_buf, strerror(errno));
		}
		else
		{
			fwrite(recv_buf, 1, retval, stdout);
		}
	}

	close(sfd);

	exit(0);
FailExit:
	if(sfd != -1)
	{
		close(sfd);
	}
	if(result) freeaddrinfo(result);
	exit(1);
}

void show_help(char* argv0)
{
	printf("Usage: %s [-e -h -p] or [-d|-s -c -l]\n", argv0);
	printf("Options:\n");
	printf("  -e <command>   Execute command through an running daemon\n");
	printf("  -h <host>      Specify daemon host address, dafault is "DEFAULT_DAEMON_HOST"\n");
	printf("  -p <port>      Specify daemon port, default is %d\n", DEFAULT_DAEMON_PORT);
	printf("  -d             Run the daemon\n");
	printf("  -s             Run the daemon but don't daemonize\n");
	printf("  -c <path>      Set configure file path\n");
	printf("  -l <path>      Set log file path\n");
}

int main(int argc, char** argv)
{
	int run_daemonize = 0;
	int run_non_daemonize = 0;
	char *cfg_filepath = NULL;
	char *log_filepath = NULL;
	char *exec_command = NULL;
	char *daemon_address = NULL;
	int daemon_port = 0;

	if(argc <= 1)
	{
		show_help(argv[0]);
		return 1;
	}

	for(;;)
	{
		int opt = getopt(argc, argv, "e:h:p:dsc:l:");
		if (opt == -1) break;
		switch(opt)
		{
		case 'e':
			exec_command = optarg;
			break;
		case 'h':
			daemon_address = optarg;
			break;
		case 'p':
			if(sscanf(optarg, "%d", &daemon_port) != 1)
			{
				fprintf (stderr, "Invalid port number '%s'.\n", optarg);
				return 1;
			}
			break;
		case 'd':
			run_daemonize = 1;
			break;
		case 's':
			run_non_daemonize = 1;
			break;
		case 'c':
			cfg_filepath = optarg;
			break;
		case 'l':
			log_filepath = optarg;
			break;
		case '?':
			switch(optopt)
			{
			case 'e':
			case 'c':
			case 'h':
			case 'p':
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				return 1;
			default:
				if (isprint (optopt))
          			fprintf (stderr, "Unknown option `-%c'.\n", optopt);
          		else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			}
			break;
		default:
			return 1;
		}
	}

	if(run_daemonize && exec_command)
	{
		fprintf (stderr, "Option -d conflicts with option -e.\n");
		return 1;
	}

	if(run_non_daemonize && exec_command)
	{
		fprintf (stderr, "Option -s conflicts with option -e.\n");
		return 1;
	}

	if(run_daemonize && run_non_daemonize)
	{
		fprintf (stderr, "Option -d conflicts with option -s.\n");
		return 1;
	}

	if(run_daemonize || run_non_daemonize)
	{
		if(daemon_address || daemon_port)
		{
			fprintf (stderr, "Option -h or option -p should be used with option -e.\n");
			return 1;
		}
		if (!cfg_filepath) cfg_filepath = CFG_FILE;
		if (!log_filepath) log_filepath = LOG_FILE;
		run_as_daemon(cfg_filepath, log_filepath, run_daemonize);
	}
	else
	{
		if (!exec_command)
		{
			fprintf (stderr, "Must specify -d or -e option.\n");
			return 1;
		}
		if (cfg_filepath || log_filepath)
		{
			fprintf (stderr, "Option -e conflicts with option -c and -l, the client of the daemon don't need any cfg files and don't write any logs.\n");
			return 1;
		}
		if (!daemon_address) daemon_address = DEFAULT_DAEMON_HOST;
		if (!daemon_port) daemon_port = DEFAULT_DAEMON_PORT;
		run_as_client(daemon_address, daemon_port, exec_command);
	}

	return 0;
}
