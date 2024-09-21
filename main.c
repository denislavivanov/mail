#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <dns.h>

#define BUFFER_SIZ 1024
#define TOTAL_SIZ  2048

struct mail_client
{
    char* buff;
    char* rcpt;
    int   sock;
    int   rcpt_cnt;
    char  domain[64];
};

in_addr_t get_mail_server(const char* domain)
{
    DNS_Client*    dns;
    DNS_MX_Answer* ans;
    int len;
    int min_idx;
    int min_pref;

    dns = dns_get_client();
    ans = dns_get_mxhost(dns, domain, &len);

    if (len == 0)
        return 0;

    min_idx  = 0;
    min_pref = ans[0].Pref;

    for (int i = 1; i < len; ++i)
    {
        if (ans[i].Pref < min_pref)
        {
            min_pref = ans[i].Pref;
            min_idx  = i;
        }
    }

    return dns_get_iphost(dns, ans[min_idx].Data);
}

void smtp_send(int sock, char* buf, size_t len)
{
    size_t sent_bytes;

    while (len > 0)
    {
        sent_bytes = send(sock, buf, len, 0);

        //TODO: add error propagation
        if (sent_bytes == -1)
            return;

        buf += sent_bytes;
        len -= sent_bytes;
    }
}

void smtp_recv(int sock, char* buf, size_t len)
{
    size_t recv_bytes;

    while (len > 0)
    {
        recv_bytes = recv(sock, buf, len, 0);

        //TODO: add error propagation
        if (recv_bytes <= 0)
            return;

        if (strstr(buf, "\r\n"))
            break;

        buf += recv_bytes;
        len -= recv_bytes;
    }

    buf[recv_bytes] = '\0';
}

_Bool smtp_msg_complete(const char* msg)
{
    char status;
    const char* line_end;
    const char* line_begin = msg;

    while ((line_end = strstr(line_begin, "\r\n")))
    {
        /* Msg line too short! */
        if (line_end - line_begin < 4)
            return 0;

        status     = line_begin[3];
        line_begin = line_end + 2;
    }

    return *line_begin == '\0' && status == ' ';
}

void smtp_get_response(struct mail_client* client,
                       int* response_code)
{
    do
    {
        smtp_recv(client->sock, client->buff, BUFFER_SIZ);   
        printf("%s", client->buff);
    } 
    while (!smtp_msg_complete(client->buff));

    sscanf(client->buff, "%d", response_code);
}

void smtp_handshake(struct mail_client* client)
{
    int response_code;

    /* Server greeting */
    smtp_get_response(client, &response_code);

    if (response_code != 220)
    {
        smtp_send(client->sock, "QUIT\r\n", 6);
        fprintf(stderr, "* SMTP handshake fail! Code: %d\n", response_code);
        return;
    }

    smtp_send(client->sock, "EHLO ", 5);
    smtp_send(client->sock, client->domain, strlen(client->domain));

    /* Server options */
    smtp_get_response(client, &response_code);
}

void smtp_sender(struct mail_client* client, 
                 const char* sender)
{
    int response_code;

    sprintf(client->buff, "MAIL FROM:<%s>\r\n", sender);

    smtp_send(client->sock, client->buff, strlen(client->buff));
    smtp_get_response(client, &response_code);

    if (response_code != 250)
    {
        fprintf(stderr, "* SMTP sender fail:\n");
        fprintf(stderr, "%s\n", client->buff);
    }
}

void smtp_recipients(struct mail_client* client,
                     const char* recipients, int cnt)
{
    int    i;
    int    response_code;
    size_t recipient_len;

    for (i = 0; i < cnt; ++i)
    {
        recipient_len = strlen(recipients) + 1;

        sprintf(client->buff, "RCPT TO:<%s>\r\n", recipients);
        smtp_send(client->sock, client->buff, recipient_len + 11);
        smtp_get_response(client, &response_code);

        if (response_code != 250)
        {
            fprintf(stderr, "* SMTP recipients fail:\n");
            fprintf(stderr, "%s\n", client->buff);

            return;
        }

        recipients += recipient_len;
    }
}

void smtp_body(struct mail_client* client, char* body)
{
    int response_code;

    smtp_send(client->sock, "DATA\r\n", 6);
    smtp_get_response(client, &response_code);

    if (response_code != 354)
    {
        fprintf(stderr, "* SMTP fail:\n");
        fprintf(stderr, "%s\n", client->buff);

        return;
    }

    smtp_send(client->sock, body, strlen(body));
    smtp_send(client->sock, ".\r\n", 3);
    smtp_get_response(client, &response_code);

    if (response_code != 250)
    {
        fprintf(stderr, "* SMTP fail:\n");
        fprintf(stderr, "%s\n", client->buff);
    }

    smtp_send(client->sock, "QUIT\r\n", 6);
}

void smtp_build_body(char* dst, const char* subject)
{

}

void get_recipients(struct mail_client* client)
{
    size_t len;
    size_t max = 1024;
    size_t offset = 0;

    client->rcpt_cnt = 0;

    printf("Recipient(s):\n");

    do
    {
        printf("-> ");
        fgets(&client->rcpt[offset], max, stdin);
        len = strlen(&client->rcpt[offset]);

        max    -= len;
        offset += len;
        ++client->rcpt_cnt;
        client->rcpt[offset - 1] = '\0';
    }
    while (len > 1 && max > 0);

    /* Remove extra record */
    --client->rcpt_cnt;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <dst_mail>\n", *argv);
        return 1;
    }

    int    sock;
    struct sockaddr_in dest;
    struct mail_client client;

    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(25);
    dest.sin_addr.s_addr = get_mail_server(argv[1]);

    client.sock     = socket(AF_INET, SOCK_STREAM, 0);
    client.buff     = malloc(TOTAL_SIZ);
    client.rcpt     = client.buff + BUFFER_SIZ;
    strncpy(client.domain, "example.org\r\n", 64);

    assert(client.sock != -1);
    assert(client.buff != NULL);

    get_recipients(&client);

    uint64_t visited;

    char*  p = client.rcpt;
    char*  q;
    char*  domain;
    char*  curr_domain;
    size_t len;

    for (size_t i = 0; i < client.rcpt_cnt; ++i)
    {
        len = strlen(p) + 1;

        if (!(visited & (1 << i)))
        {
            curr_domain = strchr(p, '@') + 1;
            q = p;

            for (size_t j = i; j < client.rcpt_cnt; ++j)
            {
                domain = strchr(q, '@') + 1;

                if (!strcmp(domain, curr_domain))
                {
                    printf("%s\n", q);
                    visited |= (1 << j);
                }

                q += strlen(q) + 1;
            }
        }

        p += len;
    }


    // if (connect(client.sock, (struct sockaddr*)&dest, sizeof(dest)) < 0)
    // {
    //     perror(argv[1]);
    //     return 1;
    // }

    // smtp_handshake(&client);
    // smtp_sender(&client, "jon.doe@example.org");
    // smtp_recipients(&client, recpts, 2);

    // free(client.buff);
    // close(client.sock);
    return 0;
}
