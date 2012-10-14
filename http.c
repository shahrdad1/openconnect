/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "openconnect-internal.h"

static int proxy_write(struct openconnect_info *vpninfo, int fd,
		       unsigned char *buf, size_t len);
static int proxy_read(struct openconnect_info *vpninfo, int fd,
		      unsigned char *buf, size_t len);

#define MAX_BUF_LEN 131072
/*
 * We didn't really want to have to do this for ourselves -- one might have
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

static int http_add_cookie(struct openconnect_info *vpninfo,
			   const char *option, const char *value)
{
	struct vpn_option *new, **this;

	if (*value) {
		new = malloc(sizeof(*new));
		if (!new) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No memory for allocating cookies\n"));
			return -ENOMEM;
		}
		new->next = NULL;
		new->option = strdup(option);
		new->value = strdup(value);
		if (!new->option || !new->value) {
			free(new->option);
			free(new->value);
			free(new);
			return -ENOMEM;
		}
	} else {
		/* Kill cookie; don't replace it */
		new = NULL;
	}
	for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
		if (!strcmp(option, (*this)->option)) {
			/* Replace existing cookie */
			if (new)
				new->next = (*this)->next;
			else
				new = (*this)->next;
			
			free((*this)->option);
			free((*this)->value);
			free(*this);
			*this = new;
			break;
		}
	}
	if (new && !*this) {
		*this = new;
		new->next = NULL;
	}
	return 0;
}

#define BODY_HTTP10 -1
#define BODY_CHUNKED -2

static int process_http_response(struct openconnect_info *vpninfo, int *result,
				 int (*header_cb)(struct openconnect_info *, char *, char *),
				 char **body_ret)
{
	char buf[MAX_BUF_LEN];
	char *body = NULL;
	int bodylen = BODY_HTTP10;
	int done = 0;
	int closeconn = 0;
	int i;

 cont:
	if (openconnect_SSL_gets(vpninfo, buf, sizeof(buf)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error fetching HTTPS response\n"));
		return -EINVAL;
	}

	if (!strncmp(buf, "HTTP/1.0 ", 9))
		closeconn = 1;
	
	if ((!closeconn && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse HTTP response '%s'\n"), buf);
		return -EINVAL;
	}

	vpn_progress(vpninfo, (*result==200)?PRG_TRACE:PRG_INFO,
		     _("Got HTTP response: %s\n"), buf);

	/* Eat headers... */
	while ((i = openconnect_SSL_gets(vpninfo, buf, sizeof(buf)))) {
		char *colon;

		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error processing HTTP response\n"));
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Ignoring unknown HTTP response line '%s'\n"), buf);
			continue;
		}
		*(colon++) = 0;
		if (*colon == ' ')
			colon++;

		/* Handle Set-Cookie first so that we can avoid printing the
		   webvpn cookie in the verbose debug output */
		if (!strcasecmp(buf, "Set-Cookie")) {
			char *semicolon = strchr(colon, ';');
			const char *print_equals;
			char *equals = strchr(colon, '=');
			int ret;

			if (semicolon)
				*semicolon = 0;

			if (!equals) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Invalid cookie offered: %s\n"), buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			print_equals = equals;
			/* Don't print the webvpn cookie unless it's empty; we don't
			   want people posting it in public with debugging output */
			if (!strcmp(colon, "webvpn") && *equals)
				print_equals = _("<elided>");
			vpn_progress(vpninfo, PRG_TRACE, "%s: %s=%s%s%s\n",
				     buf, colon, print_equals, semicolon?";":"",
				     semicolon?(semicolon+1):"");

			/* The server tends to ask for the username and password as
			   usual, even if we've already failed because it didn't like
			   our cert. Thankfully it does give us this hint... */
			if (!strcmp(colon, "ClientCertAuthFailed"))
				vpn_progress(vpninfo, PRG_ERR,
					     _("SSL certificate authentication failed\n"));

			ret = http_add_cookie(vpninfo, colon, equals);
			if (ret)
				return ret;
		} else {
			vpn_progress(vpninfo, PRG_TRACE, "%s: %s\n", buf, colon);
		}

		if (!strcasecmp(buf, "Connection")) {
			if (!strcasecmp(colon, "Close"))
				closeconn = 1;
#if 0
			/* This might seem reasonable, but in fact it breaks
			   certificate authentication with some servers. If
			   they give an HTTP/1.0 response, even if they
			   explicitly give a Connection: Keep-Alive header,
			   just close the connection. */
			else if (!strcasecmp(colon, "Keep-Alive"))
				closeconn = 0;
#endif
		}
		if (!strcasecmp(buf, "Location")) {
			vpninfo->redirect_url = strdup(colon);
			if (!vpninfo->redirect_url)
				return -ENOMEM;
		}
		if (!strcasecmp(buf, "Content-Length")) {
			bodylen = atoi(colon);
			if (bodylen < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Response body has negative size (%d)\n"),
					     bodylen);
				return -EINVAL;
			}
		}
		if (!strcasecmp(buf, "Transfer-Encoding")) {
			if (!strcasecmp(colon, "chunked"))
				bodylen = BODY_CHUNKED;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown Transfer-Encoding: %s\n"),
					     colon);
				return -EINVAL;
			}
		}
		if (header_cb && !strncmp(buf, "X-", 2))
			header_cb(vpninfo, buf, colon);
	}

	/* Handle 'HTTP/1.1 100 Continue'. Not that we should ever see it */
	if (*result == 100)
		goto cont;

	/* Now the body, if there is one */
	vpn_progress(vpninfo, PRG_TRACE, _("HTTP body %s (%d)\n"), 
		     bodylen==BODY_HTTP10?"http 1.0" :
		     bodylen==BODY_CHUNKED?"chunked" : "length: ",
		     bodylen);

	/* If we were given Content-Length, it's nice and easy... */
	if (bodylen > 0) {
		body = malloc(bodylen + 1);
		if (!body)
			return -ENOMEM;
		while (done < bodylen) {
			i = openconnect_SSL_read(vpninfo, body + done, bodylen - done);
			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error reading HTTP response body\n"));
                                free(body);
				return -EINVAL;
			}
			done += i;
		}
	} else if (bodylen == BODY_CHUNKED) {
		/* ... else, chunked */
		while ((i = openconnect_SSL_gets(vpninfo, buf, sizeof(buf)))) {
			int chunklen, lastchunk = 0;

			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error fetching chunk header\n"));
				return i;
			}
			chunklen = strtol(buf, NULL, 16);
			if (!chunklen) {
				lastchunk = 1;
				goto skip;
			}
			body = realloc(body, done + chunklen + 1);
			if (!body)
				return -ENOMEM;
			while (chunklen) {
				i = openconnect_SSL_read(vpninfo, body + done, chunklen);
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error reading HTTP response body\n"));
                                        free(body);
					return -EINVAL;
				}
				chunklen -= i;
				done += i;
			}
		skip:
			if ((i = openconnect_SSL_gets(vpninfo, buf, sizeof(buf)))) {
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error fetching HTTP response body\n"));
				} else {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error in chunked decoding. Expected '', got: '%s'"),
						     buf);
				}
                                free(body);
				return -EINVAL;
			}

			if (lastchunk)
				break;
		}
	} else if (bodylen == BODY_HTTP10) {
		if (!closeconn) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cannot receive HTTP 1.0 body without closing connection\n"));
			return -EINVAL;
		}

		/* HTTP 1.0 response. Just eat all we can in 16KiB chunks */
		while (1) {
			body = realloc(body, done + 16384);
			if (!body)
				return -ENOMEM;
			i = openconnect_SSL_read(vpninfo, body + done, 16384);
			if (i > 0) {
				/* Got more data */
				done += i;
			} else if (i < 0) {
				/* Error */
				free(body);
				return i;
			} else {
				/* Connection closed. Reduce allocation to just what we need */
				body = realloc(body, done + 1);
				if (!body)
					return -ENOMEM;
				break;
                        }
		}
	}

	if (closeconn || vpninfo->no_http_keepalive)
		openconnect_close_https(vpninfo, 0);

	if (body)
		body[done] = 0;
	*body_ret = body;
	return done;
}

static int fetch_config(struct openconnect_info *vpninfo, char *fu, char *bu,
			char *server_sha1)
{
	struct vpn_option *opt;
	char buf[MAX_BUF_LEN];
	char *config_buf = NULL;
	int result, buflen;
	unsigned char local_sha1_bin[SHA1_SIZE];
	char local_sha1_ascii[(SHA1_SIZE * 2)+1];
	int i;

	if (openconnect_open_https(vpninfo)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open HTTPS connection to %s\n"),
			     vpninfo->hostname);
		return -EINVAL;
	}

	sprintf(buf, "GET %s%s HTTP/1.1\r\n", fu, bu);
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");

	if (openconnect_SSL_write(vpninfo, buf, strlen(buf)) != strlen(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send GET request for new config\n"));
		return -EIO;
	}

	buflen = process_http_response(vpninfo, &result, NULL, &config_buf);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return -EINVAL;
	}

	if (result != 200) {
		free(config_buf);
		return -EINVAL;
	}

	openconnect_sha1(local_sha1_bin, config_buf, buflen);

	for (i = 0; i < SHA1_SIZE; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(server_sha1, local_sha1_ascii)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Downloaded config file did not match intended SHA1\n"));
		free(config_buf);
		return -EINVAL;
	}

	result = vpninfo->write_new_config(vpninfo->cbdata, config_buf, buflen);
	free(config_buf);
	return result;
}

static int run_csd_script(struct openconnect_info *vpninfo, char *buf, int buflen)
{
	char fname[16];
	int fd, ret;

	if (!vpninfo->uid_csd_given && !vpninfo->csd_wrapper) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.\n"
			       "This facility is disabled by default for security reasons, so you may wish to enable it."));
		return -EPERM;
	}

#ifndef __linux__
	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run Linux CSD trojan script."));
#endif

	sprintf(fname, "/tmp/csdXXXXXX");
	fd = mkstemp(fname);
	if (fd < 0) {
		int err = -errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open temporary CSD script file: %s\n"),
			     strerror(errno));
		return err;
	}

	ret = proxy_write(vpninfo, fd, (void *)buf, buflen);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to write temporary CSD script file: %s\n"),
			     strerror(-ret));
		return ret;
	}
	fchmod(fd, 0755);
	close(fd);

	if (!fork()) {
		char scertbuf[MD5_SIZE * 2 + 1];
		char ccertbuf[MD5_SIZE * 2 + 1];
		char *csd_argv[32];
		int i = 0;

		if (vpninfo->uid_csd_given && vpninfo->uid_csd != getuid()) {
			struct passwd *pw;

			if (setuid(vpninfo->uid_csd)) {
				fprintf(stderr, _("Failed to set uid %ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			if (!(pw = getpwuid(vpninfo->uid_csd))) {
				fprintf(stderr, _("Invalid user uid=%ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			setenv("HOME", pw->pw_dir, 1);
			if (chdir(pw->pw_dir)) {
				fprintf(stderr, _("Failed to change to CSD home directory '%s': %s\n"),
					pw->pw_dir, strerror(errno));
				exit(1);
			}
		}
		if (getuid() == 0 && !vpninfo->csd_wrapper) {
			fprintf(stderr, _("Warning: you are running insecure "
					  "CSD code with root privileges\n"
					  "\t Use command line option \"--csd-user\"\n"));
		}
		if (vpninfo->uid_csd_given == 2) {
			/* The NM tool really needs not to get spurious output
			   on stdout, which the CSD trojan spews. */
			dup2(2, 1);
		}
		if (vpninfo->csd_wrapper)
			csd_argv[i++] = vpninfo->csd_wrapper;
		csd_argv[i++] = fname;
		csd_argv[i++]= (char *)"-ticket";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->csd_ticket) == -1)
			return -ENOMEM;
		csd_argv[i++]= (char *)"-stub";
		csd_argv[i++]= (char *)"\"0\"";
		csd_argv[i++]= (char *)"-group";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->authgroup?:"") == -1)
			return -ENOMEM;

		openconnect_local_cert_md5(vpninfo, ccertbuf);
		scertbuf[0] = 0;
		get_cert_md5_fingerprint(vpninfo, vpninfo->peer_cert, scertbuf);
		csd_argv[i++]= (char *)"-certhash";
		if (asprintf(&csd_argv[i++], "\"%s:%s\"", scertbuf, ccertbuf) == -1)
			return -ENOMEM;

		csd_argv[i++]= (char *)"-url";
		if (asprintf(&csd_argv[i++], "\"https://%s%s\"", vpninfo->hostname, vpninfo->csd_starturl) == -1)
			return -ENOMEM;

		csd_argv[i++]= (char *)"-langselen";
		csd_argv[i++] = NULL;

		execv(csd_argv[0], csd_argv);
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to exec CSD script %s\n"), csd_argv[0]);
		exit(1);
	}

	free(vpninfo->csd_stuburl);
	vpninfo->csd_stuburl = NULL;
	vpninfo->urlpath = strdup(vpninfo->csd_waiturl +
				  (vpninfo->csd_waiturl[0] == '/' ? 1 : 0));
	vpninfo->csd_waiturl = NULL;
	vpninfo->csd_scriptname = strdup(fname);

	http_add_cookie(vpninfo, "sdesktop", vpninfo->csd_token);

	return 0;
}

int internal_parse_url(char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port)
{
	char *proto = url;
	char *host, *path, *port_str;
	int port;

	host = strstr(url, "://");
	if (host) {
		*host = 0;
		host += 3;

		if (!strcasecmp(proto, "https"))
			port = 443;
		else if (!strcasecmp(proto, "http"))
			port = 80;
		else if (!strcasecmp(proto, "socks") ||
			 !strcasecmp(proto, "socks4") ||
			 !strcasecmp(proto, "socks5"))
			port = 1080;
		else
			return -EPROTONOSUPPORT;
	} else {
		if (default_port) {
			proto = NULL;
			port = default_port;
			host = url;
		} else
			return -EINVAL;
	}

	path = strchr(host, '/');
	if (path)
		*(path++) = 0;

	port_str = strrchr(host, ':');
	if (port_str) {
		char *end;
		int new_port = strtol(port_str + 1, &end, 10);

		if (!*end) {
			*port_str = 0;
			port = new_port;
		}
	}

	if (res_proto)
		*res_proto = proto ? strdup(proto) : NULL;
	if (res_host)
		*res_host = strdup(host);
	if (res_port)
		*res_port = port;
	if (res_path)
		*res_path = (path && *path) ? strdup(path) : NULL;

	/* Undo the damage we did to the original string */
	if (port_str)
		*(port_str) = ':';
	if (path)
		*(path - 1) = '/';
	if (proto)
		*(host - 3) = ':';
	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, no cookie (user cancel)
 *  = 1, obtained cookie
 */
int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct vpn_option *opt, *next;
	char buf[MAX_BUF_LEN];
	char *form_buf = NULL;
	int result, buflen;
	char request_body[2048];
	const char *request_body_type = NULL;
	const char *method = "GET";

	if (vpninfo->use_stoken) {
		result = prepare_stoken(vpninfo);
		if (result < 0)
			return result;
		if (result > 0)
			vpninfo->use_stoken = 0;
	}

 retry:
	if (form_buf) {
		free(form_buf);
		form_buf = NULL;
	}
	if (openconnect_open_https(vpninfo)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open HTTPS connection to %s\n"),
			     vpninfo->hostname);
		return -EINVAL;
	}

	/*
	 * It would be nice to use cURL for this, but we really need to guarantee
	 * that we'll be using OpenSSL (for the TPM stuff), and it doesn't seem
	 * to have any way to let us provide our own socket read/write functions.
	 * We can only provide a socket _open_ function. Which would require having
	 * a socketpair() and servicing the "other" end of it.
	 *
	 * So we process the HTTP for ourselves...
	 */
	sprintf(buf, "%s /%s HTTP/1.1\r\n", method, vpninfo->urlpath ?: "");
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
	if (request_body_type) {
		sprintf(buf + strlen(buf),  "Content-Type: %s\r\n",
			      request_body_type);
		sprintf(buf + strlen(buf),  "Content-Length: %zd\r\n",
			      strlen(request_body));
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");
	if (request_body_type)
		sprintf(buf + strlen(buf), "%s", request_body);

	if (vpninfo->port == 443)
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s/%s\n",
			     method, vpninfo->hostname,
			     vpninfo->urlpath ?: "");
	else
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s:%d/%s\n",
			     method, vpninfo->hostname, vpninfo->port,
			     vpninfo->urlpath ?: "");

	result = openconnect_SSL_write(vpninfo, buf, strlen(buf));
	if (result < 0)
		return result;

	buflen = process_http_response(vpninfo, &result, NULL, &form_buf);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return buflen;
	}

	if (result != 200 && vpninfo->redirect_url) {
	redirect:
		if (!strncmp(vpninfo->redirect_url, "https://", 8)) {
			/* New host. Tear down the existing connection and make a new one */
			char *host;
			int port;
			int ret;

			free(vpninfo->urlpath);
			vpninfo->urlpath = NULL;

			ret = internal_parse_url(vpninfo->redirect_url, NULL, &host, &port, &vpninfo->urlpath, 0);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to parse redirected URL '%s': %s\n"),
					     vpninfo->redirect_url, strerror(-ret));
				free(vpninfo->redirect_url);
				vpninfo->redirect_url = NULL;
				free(form_buf);
				return ret;
			}

			if (strcasecmp(vpninfo->hostname, host) || port != vpninfo->port) {
				free(vpninfo->hostname);
				vpninfo->hostname = host;
				vpninfo->port = port;

				/* Kill the existing connection, and a new one will happen */
				free(vpninfo->peer_addr);
				vpninfo->peer_addr = NULL;
				openconnect_close_https(vpninfo, 0);

				for (opt = vpninfo->cookies; opt; opt = next) {
					next = opt->next;

					free(opt->option);
					free(opt->value);
					free(opt);
				}
				vpninfo->cookies = NULL;
			} else
				free(host);

			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;

			goto retry;
		} else if (strstr(vpninfo->redirect_url, "://")) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cannot follow redirection to non-https URL '%s'\n"),
				     vpninfo->redirect_url);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			free(form_buf);
			return -EINVAL;
		} else if (vpninfo->redirect_url[0] == '/') {
			/* Absolute redirect within same host */
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(vpninfo->redirect_url + 1);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			goto retry;
		} else {
			char *lastslash = NULL;
			if (vpninfo->urlpath)
				lastslash = strrchr(vpninfo->urlpath, '/');
			if (!lastslash) {
				free(vpninfo->urlpath);
				vpninfo->urlpath = vpninfo->redirect_url;
				vpninfo->redirect_url = NULL;
			} else {
				char *oldurl = vpninfo->urlpath;
				*lastslash = 0;
				vpninfo->urlpath = NULL;
				if (asprintf(&vpninfo->urlpath, "%s/%s",
					     oldurl, vpninfo->redirect_url) == -1) {
					int err = -errno;
					vpn_progress(vpninfo, PRG_ERR,
						     _("Allocating new path for relative redirect failed: %s\n"),
						     strerror(-err));
					return err;
				}
				free(oldurl);
				free(vpninfo->redirect_url);
				vpninfo->redirect_url = NULL;
			}
			goto retry;
		}
	}
	if (!form_buf || result != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     result);
		free(form_buf);
		return -EINVAL;
	}
	if (vpninfo->csd_stuburl) {
		/* This is the CSD stub script, which we now need to run */
		result = run_csd_script(vpninfo, form_buf, buflen);
		if (result) {
			free(form_buf);
			return result;
		}

		/* Now we'll be redirected to the waiturl */
		goto retry;
	}
	if (strncmp(form_buf, "<?xml", 5)) {
		/* Not XML? Perhaps it's HTML with a refresh... */
		if (strcasestr(form_buf, "http-equiv=\"refresh\"")) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Refreshing %s after 1 second...\n"),
				     vpninfo->urlpath);
			sleep(1);
			goto retry;
		}
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown response from server\n"));
		free(form_buf);
		return -EINVAL;
	}
	request_body[0] = 0;
	result = parse_xml_response(vpninfo, form_buf, request_body, sizeof(request_body),
				    &method, &request_body_type);

	if (!result)
		goto redirect;

	free(form_buf);

	if (result != 2)
		return result;

	/* A return value of 2 means the XML form indicated
	   success. We _should_ have a cookie... */

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn"))
			vpninfo->cookie = opt->value;
		else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3)) {
					if (!strncasecmp(tok+3, vpninfo->xmlsha1,
							 SHA1_SIZE * 2))
						break;
					sha = tok + 3;
				}
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha)
				fetch_config(vpninfo, bu, fu, sha);
		}
	}
	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
		vpninfo->csd_scriptname = NULL;
	}
	return 0;
}

char *openconnect_create_useragent(const char *base)
{
	char *uagent;

	if (asprintf(&uagent, "%s %s", base, openconnect_version_str) < 0)
		return NULL;

	return uagent;
}

static int proxy_gets(struct openconnect_info *vpninfo, int fd,
		      char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ( (ret = proxy_read(vpninfo, fd, (void *)(buf + i), 1)) == 0) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

static int proxy_write(struct openconnect_info *vpninfo, int fd,
		       unsigned char *buf, size_t len)
{
	size_t count;

	for (count = 0; count < len; ) {
		fd_set rd_set, wr_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);
		FD_SET(fd, &wr_set);
		if (vpninfo->cancel_fd != -1) {
			FD_SET(vpninfo->cancel_fd, &rd_set);
			if (vpninfo->cancel_fd > fd)
				maxfd = vpninfo->cancel_fd;
		}

		select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
		if (vpninfo->cancel_fd != -1 &&
		    FD_ISSET(vpninfo->cancel_fd, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &wr_set))
			continue;

		i = write(fd, buf + count, len - count);
		if (i < 0)
			return -errno;

		count += i;
	}
	return 0;
}

static int proxy_read(struct openconnect_info *vpninfo, int fd,
		      unsigned char *buf, size_t len)
{
	size_t count;

	for (count = 0; count < len; ) {
		fd_set rd_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&rd_set);
		FD_SET(fd, &rd_set);
		if (vpninfo->cancel_fd != -1) {
			FD_SET(vpninfo->cancel_fd, &rd_set);
			if (vpninfo->cancel_fd > fd)
				maxfd = vpninfo->cancel_fd;
		}

		select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (vpninfo->cancel_fd != -1 &&
		    FD_ISSET(vpninfo->cancel_fd, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &rd_set))
			continue;

		i = read(fd, buf + count, len - count);
		if (i < 0)
			return -errno;

		count += i;
	}
	return 0;
}

static const char *socks_errors[] = {
	N_("request granted"),
	N_("general failure"),
	N_("connection not allowed by ruleset"),
	N_("network unreachable"),
	N_("host unreachable"),
	N_("connection refused by destination host"),
	N_("TTL expired"),
	N_("command not supported / protocol error"),
	N_("address type not supported")
};

static int process_socks_proxy(struct openconnect_info *vpninfo, int ssl_sock)
{
	unsigned char buf[1024];
	int i;

	buf[0] = 5; /* SOCKS version */
	buf[1] = 1; /* # auth methods */
	buf[2] = 0; /* No auth supported */

	if ((i = proxy_write(vpninfo, ssl_sock, buf, 3))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing auth request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	
	if ((i = proxy_read(vpninfo, ssl_sock, buf, 2))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading auth response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected auth response from SOCKS proxy: %02x %02x\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1]) {
	socks_err:
		if (buf[1] < sizeof(socks_errors) / sizeof(socks_errors[0]))
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x: %s\n"),
				     buf[1], _(socks_errors[buf[1]]));
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x\n"),
				     buf[1]);
		return -EIO;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting SOCKS proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

	buf[0] = 5; /* SOCKS version */
	buf[1] = 1; /* CONNECT */
	buf[2] = 0; /* Reserved */
	buf[3] = 3; /* Address type is domain name */
	buf[4] = strlen(vpninfo->hostname);
	strcpy((char *)buf + 5, vpninfo->hostname);
	i = strlen(vpninfo->hostname) + 5;
	buf[i++] = vpninfo->port >> 8;
	buf[i++] = vpninfo->port & 0xff;

	if ((i = proxy_write(vpninfo, ssl_sock, buf, i))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing connect request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	/* Read 5 bytes -- up to and including the first byte of the returned
	   address (which might be the length byte of a domain name) */
	if ((i = proxy_read(vpninfo, ssl_sock, buf, 5))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected connect response from SOCKS proxy: %02x %02x...\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1])
		goto socks_err;

	/* Connect responses contain an address */
	switch(buf[3]) {
	case 1: /* Legacy IP */
		i = 5;
		break;
	case 3: /* Domain name */
		i = buf[4] + 2;
		break;
	case 4: /* IPv6 */
		i = 17;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected address type %02x in SOCKS connect response\n"),
			     buf[3]);
		return -EIO;
	}

	if ((i = proxy_read(vpninfo, ssl_sock, buf, i))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	return 0;
}

static int process_http_proxy(struct openconnect_info *vpninfo, int ssl_sock)
{
	char buf[MAX_BUF_LEN];
	int buflen, result;

	sprintf(buf, "CONNECT %s:%d HTTP/1.1\r\n", vpninfo->hostname, vpninfo->port);
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf), "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf), "Proxy-Connection: keep-alive\r\n");
	sprintf(buf + strlen(buf), "Connection: keep-alive\r\n");
	sprintf(buf + strlen(buf), "Accept-Encoding: identity\r\n");
	sprintf(buf + strlen(buf), "\r\n");

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting HTTP proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

	result = proxy_write(vpninfo, ssl_sock, (unsigned char *)buf, strlen(buf));
	if (result) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Sending proxy request failed: %s\n"),
			     strerror(-result));
		return result;
	}

	if (proxy_gets(vpninfo, ssl_sock, buf, sizeof(buf)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error fetching proxy response\n"));
		return -EIO;
	}

	if (strncmp(buf, "HTTP/1.", 7) || (buf[7] != '0' && buf[7] != '1') ||
	    buf[8] != ' ' || !(result = atoi(buf+9))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse proxy response '%s'\n"), buf);
		return -EINVAL;
	}

	if (result != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Proxy CONNECT request failed: %s\n"), buf);
		return -EIO;
	}

	while ((buflen = proxy_gets(vpninfo, ssl_sock, buf, sizeof(buf)))) {
		if (buflen < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read proxy response\n"));
			return -EIO;
		}
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected continuation line after CONNECT response: '%s'\n"),
			     buf);
	}

	return 0;
}

int process_proxy(struct openconnect_info *vpninfo, int ssl_sock)
{
	if (!vpninfo->proxy_type || !strcmp(vpninfo->proxy_type, "http"))
		return process_http_proxy(vpninfo, ssl_sock);
	
	if (!strcmp(vpninfo->proxy_type, "socks") ||
	    !strcmp(vpninfo->proxy_type, "socks5"))
		return process_socks_proxy(vpninfo, ssl_sock);

	vpn_progress(vpninfo, PRG_ERR, _("Unknown proxy type '%s'\n"),
		     vpninfo->proxy_type);
	return -EIO;
}

int openconnect_set_http_proxy(struct openconnect_info *vpninfo, char *proxy)
{
	char *url = proxy;
	int ret;

	if (!url)
		return -ENOMEM;

	free(vpninfo->proxy_type);
	vpninfo->proxy_type = NULL;
	free(vpninfo->proxy);
	vpninfo->proxy = NULL;

	ret = internal_parse_url(url, &vpninfo->proxy_type, &vpninfo->proxy,
				 &vpninfo->proxy_port, NULL, 80);
	if (ret)
		goto out;

	if (vpninfo->proxy_type &&
	    strcmp(vpninfo->proxy_type, "http") &&
	    strcmp(vpninfo->proxy_type, "socks") &&
	    strcmp(vpninfo->proxy_type, "socks5")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only http or socks(5) proxies supported\n"));
		free(vpninfo->proxy_type);
		vpninfo->proxy_type = NULL;
		free(vpninfo->proxy);
		vpninfo->proxy = NULL;
		return -EINVAL;
	}
 out:
	free(url);
	return ret;
}
