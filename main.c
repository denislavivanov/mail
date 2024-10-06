#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#ifdef _WIN32
    #include <WinSock2.h>
    #include <WinDNS.h>
    
    typedef u_long in_addr_t;
#else
    #include <unistd.h>
    #include <dns.h>
#endif

#define BUFFER_SIZ 1024
#define TOTAL_SIZ  2048

struct SMTP_Client
{
    char* Buff;
    char* Rcpt;
    int   Sock;
    int   RcptCnt;
    char  Domain[64];
};

in_addr_t get_mail_server(const char* domain)
{
#ifdef _WIN32
    DNS_STATUS  result;
    PDNS_RECORD mx_rr, in_rr, min_rr;
    DWORD       min_pref;
    in_addr_t   addr;

    result = DnsQuery_A(
        domain,
        DNS_TYPE_MX,
        DNS_QUERY_STANDARD,
        NULL,
        &mx_rr,
        NULL
    );

    if (result != DNS_RCODE_NOERROR)
        return 0;

    min_pref = UINT_MAX;

    for (PDNS_RECORD curr_rr = mx_rr; curr_rr != NULL; curr_rr = curr_rr->pNext)
    {
        if (curr_rr->wType == DNS_TYPE_MX)
        {
            if (curr_rr->Data.Mx.wPreference < min_pref)
            {
                min_pref = curr_rr->Data.Mx.wPreference;
                min_rr   = curr_rr;
            }
        }
    }

    result = DnsQuery_A(
        min_rr->Data.Mx.pNameExchange,
        DNS_TYPE_A,
        DNS_QUERY_STANDARD,
        NULL,
        &in_rr,
        NULL
    );

    if (result != DNS_RCODE_NOERROR) 
        return 0;

    addr = in_rr->Data.A.IpAddress;

    DnsRecordListFree(in_rr, DnsFreeRecordList);
    DnsRecordListFree(mx_rr, DnsFreeRecordList);

    return addr;
#else
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
#endif
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

void smtp_get_response(struct SMTP_Client* client,
                       int* response_code)
{
    do
    {
        smtp_recv(client->Sock, client->Buff, BUFFER_SIZ);   
        printf("%s", client->Buff);
    } 
    while (!smtp_msg_complete(client->Buff));

    sscanf(client->Buff, "%d", response_code);
}

void smtp_handshake(struct SMTP_Client* client)
{
    int response_code;

    /* Server greeting */
    smtp_get_response(client, &response_code);

    if (response_code != 220)
    {
        smtp_send(client->Sock, "QUIT\r\n", 6);
        fprintf(stderr, "* SMTP handshake fail! Code: %d\n", response_code);
        return;
    }

    smtp_send(client->Sock, "EHLO ", 5);
    smtp_send(client->Sock, client->Domain, strlen(client->Domain));

    /* Server options */
    smtp_get_response(client, &response_code);
}

void smtp_sender(struct SMTP_Client* client, 
                 const char* sender)
{
    int response_code;

    sprintf(client->Buff, "MAIL FROM:<%s>\r\n", sender);

    smtp_send(client->Sock, client->Buff, strlen(client->Buff));
    smtp_get_response(client, &response_code);

    if (response_code != 250)
    {
        fprintf(stderr, "* SMTP sender fail:\n");
        fprintf(stderr, "%s\n", client->Buff);
    }
}

void smtp_recipients(struct SMTP_Client* client,
                     const char* recipients, int cnt)
{
    int    i;
    int    response_code;
    size_t recipient_len;

    for (i = 0; i < cnt; ++i)
    {
        recipient_len = strlen(recipients) + 1;

        sprintf(client->Buff, "RCPT TO:<%s>\r\n", recipients);
        smtp_send(client->Sock, client->Buff, recipient_len + 11);
        smtp_get_response(client, &response_code);

        if (response_code != 250)
        {
            fprintf(stderr, "* SMTP recipients fail:\n");
            fprintf(stderr, "%s\n", client->Buff);

            return;
        }

        recipients += recipient_len;
    }
}

void smtp_body(struct SMTP_Client* client, char* body)
{
    int response_code;

    smtp_send(client->Sock, "DATA\r\n", 6);
    smtp_get_response(client, &response_code);

    if (response_code != 354)
    {
        fprintf(stderr, "* SMTP fail:\n");
        fprintf(stderr, "%s\n", client->Buff);

        return;
    }

    smtp_send(client->Sock, body, strlen(body));
    smtp_send(client->Sock, ".\r\n", 3);
    smtp_get_response(client, &response_code);

    if (response_code != 250)
    {
        fprintf(stderr, "* SMTP fail:\n");
        fprintf(stderr, "%s\n", client->Buff);
    }

    smtp_send(client->Sock, "QUIT\r\n", 6);
}

void smtp_build_body(char* dst, const char* subject)
{

}

void get_recipients(struct SMTP_Client* client)
{
    size_t len;
    size_t max = 1024;
    size_t offset = 0;

    client->RcptCnt = 0;

    printf("Recipient(s):\n");

    do
    {
        printf("-> ");
        fgets(&client->Rcpt[offset], max, stdin);
        len = strlen(&client->Rcpt[offset]);

        max    -= len;
        offset += len;
        ++client->RcptCnt;
        client->Rcpt[offset - 1] = '\0';
    }
    while (len > 1 && max > 0);

    /* Remove extra record */
    --client->RcptCnt;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <dest_mail>\n", *argv);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 0), &wsa_data);
#endif

    int    sock;
    struct sockaddr_in dest;
    struct SMTP_Client client;

    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(25);
    dest.sin_addr.s_addr = get_mail_server(argv[1]);

    client.Sock = socket(AF_INET, SOCK_STREAM, 0);
    client.Buff = malloc(TOTAL_SIZ);
    client.Rcpt = client.Buff + BUFFER_SIZ; 
    strncpy(client.Domain, "example.org\r\n", 64);

    assert(client.Sock != -1);
    assert(client.Buff != NULL);

    get_recipients(&client);

    uint64_t visited;

    char*  p = client.Rcpt;
    char*  q;
    char*  domain;
    char*  curr_domain;
    size_t len;

    for (size_t i = 0; i < client.RcptCnt; ++i)
    {
        len = strlen(p) + 1;

        if (!(visited & (1 << i)))
        {
            curr_domain = strchr(p, '@') + 1;
            q = p;

            for (size_t j = i; j < client.RcptCnt; ++j)
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


    // if (connect(client.Sock, (struct sockaddr*)&dest, sizeof(dest)) < 0)
    // {
    //     perror(argv[1]);
    //     return 1;
    // }

    // smtp_handshake(&client);
    // smtp_sender(&client, "jon.doe@example.org");
    // smtp_recipients(&client, recpts, 2);

    // free(client.Buff);
    // close(client.Sock);
    return 0;
}
