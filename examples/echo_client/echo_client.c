
#include <libws.h>
#include <libws_log.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void onmsg(ws_t ws, char *msg, uint64_t len, int binary, void *arg)
{
	int *echo_count = (int *)arg;
	
	printf("Message %d: \"%s\"\n", *echo_count, msg);
	(*echo_count)--;

	{
		char *send_msg = strdup(((*echo_count % 2) == 0) ? "Hello" : "World");
		ws_send_msg(ws, send_msg);
		free(send_msg);
	}

	if (*echo_count == 0)
	{
		printf("Got last echo\n");
                ws_close(ws);
	}
}

void onclose(ws_t ws, int status, int errtype,
             const char *reason, size_t reason_len, void *arg)
{
	printf("Closing %u\n", (uint16_t)status);
        ws_base_quit(ws_get_base(ws), 1);
}

void onconnect(ws_t ws, void *arg)
{
	char *msg = strdup("hello");
	printf("Connected!\n");
	ws_send_msg(ws, msg);
	free(msg);
}

int main(int argc, char **argv)
{
	int ret = 0;
	int i;
	ws_base_t base = NULL;
	ws_t ws = NULL;
	int echo_count = 5;
        int ssl = 1;
	ws_set_log_cb(ws_default_log_cb);
	ws_set_log_level(-1);

	printf("Echo client\n\n");

	if (ws_global_init(&base))
	{
		fprintf(stderr, "Failed to init global state.\n");
		return -1;
	}

	if (ws_init(&ws, base))
	{
		fprintf(stderr, "Failed to init websocket state.\n");
		ret = -1;
		goto fail;
	}

	ws_set_onmsg_cb(ws, onmsg, &echo_count);
	ws_set_onconnect_cb(ws, onconnect, NULL);
	ws_set_onclose_cb(ws, onclose, NULL);

	if (ssl)
	{
		ws_set_ssl_state(ws, LIBWS_SSL_SELFSIGNED);
	}
        const char* server = "echo.websocket.org";
	printf("Connect to server %s\n", server);

        if (ws_connect(ws, server, 443, "?encoding=text"))
	{
		ret = -1;
		goto fail;
	}

	ws_base_service_blocking(base);

fail:
	ws_destroy(&ws);
	ws_global_destroy(&base);
	printf("Bye bye!\n");
	return ret;
}

