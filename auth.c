/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2011 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#ifdef HAVE_LIBOATH
#include <liboath/oath.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect-internal.h"

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct __oc_auth_form *form, char *body, int bodylen);
static int can_gen_tokencode(struct openconnect_info *vpninfo,
			     struct __oc_auth_form *form, struct __oc_form_opt *opt);
static int do_gen_tokencode(struct openconnect_info *vpninfo, struct __oc_auth_form *form);

static int append_opt(char *body, int bodylen, char *opt, char *name)
{
	int len = strlen(body);

	if (len) {
		if (len >= bodylen - 1)
			return -ENOSPC;
		body[len++] = '&';
	}

	while (*opt) {
		if (isalnum((int)(unsigned char)*opt)) {
			if (len >= bodylen - 1)
				return -ENOSPC;
			body[len++] = *opt;
		} else {
			if (len >= bodylen - 3)
				return -ENOSPC;
			sprintf(body+len, "%%%02x", *opt);
			len += 3;
		}
		opt++;
	}

	if (len >= bodylen - 1)
		return -ENOSPC;
	body[len++] = '=';

	while (name && *name) {
		if (isalnum((int)(unsigned char)*name)) {
			if (len >= bodylen - 1)
				return -ENOSPC;
			body[len++] = *name;
		} else {
			if (len >= bodylen - 3)
				return -ENOSPC;
			sprintf(body+len, "%%%02X", *name);
			len += 3;
		}
		name++;
	}
	body[len] = 0;

	return 0;
}

static int append_form_opts(struct openconnect_info *vpninfo,
			    struct __oc_auth_form *form, char *body, int bodylen)
{
	struct __oc_form_opt *opt;
	int ret;

	for (opt = form->opts; opt; opt = opt->next) {
		ret = append_opt(body, bodylen, opt->u.name, opt->u.value);
		if (ret)
			return ret;
	}
	return 0;
}

static int prop_equals(xmlNode *xml_node, const char *name, const char *value)
{
	char *tmp = (char *)xmlGetProp(xml_node, (unsigned char *)name);
	int ret = 0;

	if (tmp && !strcasecmp(tmp, value))
		ret = 1;
	free(tmp);
	return ret;
}

static int parse_auth_choice(struct openconnect_info *vpninfo, struct __oc_auth_form *form,
			     xmlNode *xml_node)
{
	struct __oc_form_opt_select *opt;
	int selection = 0;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	opt->form.u.type = OC_FORM_OPT_SELECT;
	opt->form.u.name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
	opt->form.u.label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

	if (!opt->form.u.name) {
		vpn_progress(vpninfo, PRG_ERR, _("Form choice has no name\n"));
		free(opt);
		return -EINVAL;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *form_id;
		struct __oc_choice *choice;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)xml_node->name, "option"))
			continue;

		form_id = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		if (!form_id)
			form_id = (char *)xmlNodeGetContent(xml_node);
		if (!form_id)
			continue;

		opt->nr_choices++;
		realloc_inplace(opt, sizeof(*opt) +
				opt->nr_choices * sizeof(*choice));
		if (!opt)
			return -ENOMEM;

		choice = &opt->choices[opt->nr_choices-1];

		choice->u.name = form_id;
		choice->u.label = (char *)xmlNodeGetContent(xml_node);
		choice->u.auth_type = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		choice->u.override_name = (char *)xmlGetProp(xml_node, (unsigned char *)"override-name");
		choice->u.override_label = (char *)xmlGetProp(xml_node, (unsigned char *)"override-label");

		choice->second_auth = prop_equals(xml_node, "second-auth", "1");
		choice->secondary_username = (char *)xmlGetProp(xml_node,
			(unsigned char *)"secondary_username");
		choice->secondary_username_editable = prop_equals(xml_node,
			"secondary_username_editable", "true");
		choice->noaaa = prop_equals(xml_node, "noaaa", "1");

		if (prop_equals(xml_node, "selected", "true"))
			selection = opt->nr_choices - 1;
	}

	if (!strcmp(opt->form.u.name, "group_list")) {
		form->u.authgroup_field = opt->form.u.name;
		form->u.authgroup_selection = selection;
		form->authgroup_opt = opt;
	}

	/* We link the choice _first_ so it's at the top of what we present
	   to the user */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, when form was parsed
 */
static int parse_form(struct openconnect_info *vpninfo, struct __oc_auth_form *form,
		      xmlNode *xml_node)
{
	char *input_type, *input_name, *input_label;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		struct __oc_form_opt *opt, **p;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "select")) {
			if (parse_auth_choice(vpninfo, form, xml_node))
				return -EINVAL;
			continue;
		}
		if (strcmp((char *)xml_node->name, "input")) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("name %s not input\n"), xml_node->name);
			continue;
		}

		input_type = (char *)xmlGetProp(xml_node, (unsigned char *)"type");
		if (!input_type) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input type in form\n"));
			continue;
		}

		if (!strcmp(input_type, "submit") || !strcmp(input_type, "reset")) {
			free(input_type);
			continue;
		}

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input name in form\n"));
			free(input_type);
			continue;
		}
		input_label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

		opt = calloc(1, sizeof(*opt));
		if (!opt) {
			free(input_type);
			free(input_name);
			free(input_label);
			return -ENOMEM;
		}

		opt->u.name = input_name;
		opt->u.label = input_label;
		opt->second_auth = prop_equals(xml_node, "second-auth", "1");

		if (!strcmp(input_type, "hidden")) {
			opt->u.type = OC_FORM_OPT_HIDDEN;
			opt->u.value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		} else if (!strcmp(input_type, "text")) {
			opt->u.type = OC_FORM_OPT_TEXT;
		} else if (!strcmp(input_type, "password")) {
			if (vpninfo->token_mode != OC_TOKEN_MODE_NONE &&
			    (can_gen_tokencode(vpninfo, form, opt) == 0)) {
				opt->u.type = OC_FORM_OPT_TOKEN;
			} else {
				opt->u.type = OC_FORM_OPT_PASSWORD;
			}
		} else {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Unknown input type %s in form\n"),
				     input_type);
			free(input_type);
			free(input_name);
			free(input_label);
			free(opt);
			continue;
		}

		free(input_type);

		p = &form->opts;
		while (*p)
			p = &(*p)->next;

		*p = opt;
	}

	return 0;
}

static char *xmlnode_msg(xmlNode *xml_node)
{
	char *fmt = (char *)xmlNodeGetContent(xml_node);
	char *result, *params[2], *pct;
	int len;
	int nr_params = 0;

	if (!fmt || !fmt[0]) {
		free(fmt);
		return NULL;
	}

	len = strlen(fmt) + 1;

	params[0] = (char *)xmlGetProp(xml_node, (unsigned char *)"param1");
	if (params[0])
		len += strlen(params[0]);
	params[1] = (char *)xmlGetProp(xml_node, (unsigned char *)"param2");
	if (params[1])
		len += strlen(params[1]);

	result = malloc(len);
	if (!result) {
		result = fmt;
		goto out;
	}

	strcpy(result, fmt);
	free(fmt);

	for (pct = strchr(result, '%'); pct;
	     (pct = strchr(pct, '%'))) {
		int paramlen;

		/* We only cope with '%s' */
		if (pct[1] != 's')
			goto out;

		if (params[nr_params]) {
			paramlen = strlen(params[nr_params]);
			/* Move rest of fmt string up... */
			memmove(pct - 1 + paramlen, pct + 2, strlen(pct) - 1);
			/* ... and put the string parameter in where the '%s' was */
			memcpy(pct, params[nr_params], paramlen);
			pct += paramlen;
		} else
			pct++;

		if (++nr_params == 2)
			break;
	}
 out:
	free(params[0]);
	free(params[1]);
	return result;
}

static int xmlnode_is_named(xmlNode *xml_node, const char *name)
{
	return !strcmp((char *)xml_node->name, name);
}

static int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);

	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

static int xmlnode_get_text(xmlNode *xml_node, const char *name, char **var)
{
	char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = xmlnode_msg(xml_node);
	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

/*
 * Legacy server response looks like:
 *
 * <auth id="<!-- "main" for initial attempt, "success" means we have a cookie -->">
 *   <title><!-- title to display to user --></title>
 *   <csd token="<!-- save to vpninfo->csd_token -->"
 *        ticket="<!-- save to vpninfo->csd_ticket -->" />
 *   <csd stuburl="<!-- ignore -->"
 *        starturl="<!-- ignore -->"
 *        waiturl="<!-- ignore -->"
 *   <csdMac
 *           stuburl="<!-- save to vpninfo->csd_stuburl on Mac only -->"
 *           starturl="<!-- save to vpninfo->csd_starturl on Mac only -->"
 *           waiturl="<!-- save to vpninfo->csd_waiturl on Mac only -->" />
 *   <csdLinux
 *             stuburl="<!-- same as above, for Linux -->"
 *             starturl="<!-- same as above, for Linux -->"
 *             waiturl="<!-- same as above, for Linux -->" />
 *   <banner><!-- display this to the user --></banner>
 *   <message>Please enter your username and password.</message>
 *   <form method="post" action="/+webvpn+/index.html">
 *     <input type="text" name="username" label="Username:" />
 *     <input type="password" name="password" label="Password:" />
 *     <input type="hidden" name="<!-- save these -->" value="<!-- ... -->" />
 *     <input type="submit" name="Login" value="Login" />
 *     <input type="reset" name="Clear" value="Clear" />
 *   </form>
 * </auth>
 *
 * New server response looks like:
 *
 * <config-auth>
 *   <version><!-- whatever --></version>
 *   <session-token><!-- if present, save to vpninfo->cookie --></session-token>
 *   <opaque>
 *     <!-- this could contain anything; copy to vpninfo->opaque_srvdata -->
 *     <tunnel-group>foobar</tunnel-group>
 *     <config-hash>1234567</config-hash>
 *   </opaque>
 *   <auth id="<!-- see above -->
 *     <!-- all of our old familiar fields -->
 *   </auth>
 *   <host-scan>
 *     <host-scan-ticket><!-- save to vpninfo->csd_ticket --></host-scan-ticket>
 *     <host-scan-token><!-- save to vpninfo->csd_token --></host-scan-token>
 *     <host-scan-base-uri><!-- save to vpninfo->csd_starturl --></host-scan-base-uri>
 *     <host-scan-wait-uri><!-- save to vpninfo->csd_waiturl --></host-scan-wait-uri>
 *   </host-scan>
 * </config-auth>
 *
 * Notes:
 *
 * 1) The new host-scan-*-uri nodes do not map directly to the old CSD fields.
 *
 * 2) The new <form> tag tends to omit the method/action properties.
 */

static int parse_auth_node(struct openconnect_info *vpninfo, xmlNode *xml_node,
			   struct __oc_auth_form *form)
{
	int ret = 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "banner", &form->u.banner);
		xmlnode_get_text(xml_node, "message", &form->u.message);
		xmlnode_get_text(xml_node, "error", &form->u.error);

		if (xmlnode_is_named(xml_node, "form")) {

			/* defaults for new XML POST */
			form->u.method = strdup("POST");
			form->u.action = strdup("/");

			xmlnode_get_prop(xml_node, "method", &form->u.method);
			xmlnode_get_prop(xml_node, "action", &form->u.action);

			if (!form->u.method || !form->u.action ||
			    strcasecmp(form->u.method, "POST") || !form->u.action[0]) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Cannot handle form method='%s', action='%s'\n"),
					     form->u.method, form->u.action);
				ret = -EINVAL;
				goto out;
			}

			ret = parse_form(vpninfo, form, xml_node);
			if (ret < 0)
				goto out;
		} else if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, "csd")) {
			xmlnode_get_prop(xml_node, "token", &vpninfo->csd_token);
			xmlnode_get_prop(xml_node, "ticket", &vpninfo->csd_ticket);
		} else if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, vpninfo->csd_xmltag)) {
			/* ignore the CSD trojan binary on mobile platforms */
			if (!vpninfo->csd_nostub)
				xmlnode_get_prop(xml_node, "stuburl", &vpninfo->csd_stuburl);
			xmlnode_get_prop(xml_node, "starturl", &vpninfo->csd_starturl);
			xmlnode_get_prop(xml_node, "waiturl", &vpninfo->csd_waiturl);
			vpninfo->csd_preurl = strdup(vpninfo->urlpath);
		}
	}

out:
	return ret;
}

static int parse_host_scan_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	/* ignore this whole section if the CSD trojan has already run */
	if (vpninfo->csd_scriptname)
		return 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "host-scan-ticket", &vpninfo->csd_ticket);
		xmlnode_get_text(xml_node, "host-scan-token", &vpninfo->csd_token);
		xmlnode_get_text(xml_node, "host-scan-base-uri", &vpninfo->csd_starturl);
		xmlnode_get_text(xml_node, "host-scan-wait-uri", &vpninfo->csd_waiturl);
	}
	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
int parse_xml_response(struct openconnect_info *vpninfo, char *response, struct __oc_auth_form **formp, int *cert_rq)
{
	struct __oc_auth_form *form;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int ret;

	if (*formp) {
		free_auth_form(*formp);
		*formp = NULL;
	}
	if (cert_rq)
		*cert_rq = 0;

	if (!response) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;
	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Response was:%s\n"), response);
		free(form);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	while (xml_node) {
		ret = 0;

		if (xml_node->type != XML_ELEMENT_NODE) {
			xml_node = xml_node->next;
			continue;
		}
		if (xmlnode_is_named(xml_node, "config-auth")) {
			/* if we do have a config-auth node, it is the root element */
			xml_node = xml_node->children;
			continue;
		} else if (xmlnode_is_named(xml_node, "client-cert-request")) {
			if (cert_rq)
				*cert_rq = 1;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Received <client-cert-request> when not expected.\n"));
				ret = -EINVAL;
			}
		} else if (xmlnode_is_named(xml_node, "auth")) {
			xmlnode_get_prop(xml_node, "id", &form->u.auth_id);
			ret = parse_auth_node(vpninfo, xml_node, form);
		} else if (xmlnode_is_named(xml_node, "opaque")) {
			if (vpninfo->opaque_srvdata)
				xmlFreeNode(vpninfo->opaque_srvdata);
			vpninfo->opaque_srvdata = xmlCopyNode(xml_node, 1);
			if (!vpninfo->opaque_srvdata)
				ret = -ENOMEM;
		} else if (xmlnode_is_named(xml_node, "host-scan")) {
			ret = parse_host_scan_node(vpninfo, xml_node);
		} else {
			xmlnode_get_text(xml_node, "session-token", &vpninfo->cookie);
			xmlnode_get_text(xml_node, "error", &form->u.error);
		}

		if (ret)
			goto out;
		xml_node = xml_node->next;
	}

	if (!form->u.auth_id && (!cert_rq || !*cert_rq)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("XML response has no \"auth\" node\n"));
		ret = -EINVAL;
		goto out;
	}

	*formp = form;
	xmlFreeDoc(xml_doc);
	return 0;

 out:
	xmlFreeDoc(xml_doc);
	free_auth_form(form);
	return ret;
}

static int dup_select_opt(struct __oc_form_opt_select *sopt)
{
	struct oc_form_opt_select *usopt;
	int i;

	if (!sopt->nr_choices)
		return -EINVAL;

	usopt = calloc(1, sizeof(*usopt) + sizeof(struct oc_choice) * sopt->nr_choices);
	if (!usopt)
		return -ENOMEM;

	usopt->form = sopt->form.u;
	usopt->nr_choices = sopt->nr_choices;
	for (i = 0; i < usopt->nr_choices; i++)
		usopt->choices[i] = sopt->choices[i].u;
	sopt->u = usopt;
	return 0;
}

int process_auth_form(struct openconnect_info *vpninfo, struct __oc_auth_form *form)
{
	int ret;
	struct __oc_form_opt *opt;
	struct oc_form_opt **last;
	struct __oc_form_opt_select *grp = form->authgroup_opt;
	struct __oc_choice *auth_choice;

	if (!vpninfo->process_auth_form) {
		vpn_progress(vpninfo, PRG_ERR, _("No form handler; cannot authenticate.\n"));
		return OC_FORM_RESULT_ERR;
	}

retry:
	auth_choice = NULL;
	if (grp && grp->nr_choices && !vpninfo->xmlpost) {
		if (vpninfo->authgroup) {
			/* For non-XML-POST, the server doesn't tell us which group is selected */
			int i;
			for (i = 0; i < grp->nr_choices; i++)
				if (!strcmp(grp->choices[i].u.name, vpninfo->authgroup))
					form->u.authgroup_selection = i;
		}
		auth_choice = &grp->choices[form->u.authgroup_selection];
	}

	/* We have two parallel linked lists of form fields here:
	   form->u.opts is a linked list of user-visible oc_form_opt's
	   form->opts is a linked list of internally-visible __oc_form_opt's
	   The former may omit fields contained in the latter. */
	last = &form->u.opts;

	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->u.type == OC_FORM_OPT_SELECT) {
			struct __oc_form_opt_select *sopt = (void *)opt;

			if (dup_select_opt(sopt) < 0)
				continue;
			*last = (struct oc_form_opt *)sopt->u;
			last = &sopt->u->form.next;
			continue;
		} else if (!auth_choice) {
			/* nothing left to check */
		} else if (auth_choice->noaaa &&
			   (opt->u.type == OC_FORM_OPT_TEXT || opt->u.type == OC_FORM_OPT_PASSWORD)) {
			/* nuke all text fields for noaaa groups */
			continue;
		} else if (!auth_choice->second_auth && opt->second_auth) {
			/* hide second-auth fields if a non-second-auth group is selected */
			continue;
		} else if (!strcmp(opt->u.name, "secondary_username") && opt->second_auth) {
			if (auth_choice->secondary_username) {
				free(opt->u.value);
				opt->u.value = strdup(auth_choice->secondary_username);
			}
			if (!auth_choice->secondary_username_editable)
				continue;
		}
		*last = &opt->u;
		last = &opt->u.next;
	}
	*last = NULL;
	ret = vpninfo->process_auth_form(vpninfo->cbdata, &form->u);

	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->u.type == OC_FORM_OPT_SELECT) {
			struct __oc_form_opt_select *sopt = (void *)opt;
			sopt->form.u.value = sopt->u->form.value;
			free(sopt->u);
			sopt->u = NULL;
		}
	}

	if (ret == OC_FORM_RESULT_NEWGROUP &&
	    form->authgroup_opt &&
	    form->authgroup_opt->form.u.value) {
		free(vpninfo->authgroup);
		vpninfo->authgroup = strdup(form->authgroup_opt->form.u.value);

		if (!vpninfo->xmlpost)
			goto retry;
	}

	return ret;
}

/* Return value:
 *  < 0, on error
 *  = OC_FORM_RESULT_OK (0), when form parsed and POST required
 *  = OC_FORM_RESULT_CANCELLED, when response was cancelled by user
 *  = __OC_FORM_RESULT_LOGGEDIN, when form indicates that login was already successful
 */
int handle_auth_form(struct openconnect_info *vpninfo, struct __oc_auth_form *form,
		     char *request_body, int req_len, const char **method,
		     const char **request_body_type)
{
	int ret;
	struct oc_vpn_option *opt, *next;

	if (!strcmp(form->u.auth_id, "success"))
		return __OC_FORM_RESULT_LOGGEDIN;

	if (vpninfo->nopasswd) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Asked for password but '--no-passwd' set\n"));
		return -EPERM;
	}

	if (vpninfo->csd_token && vpninfo->csd_ticket && vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		/* AB: remove all cookies */
		for (opt = vpninfo->cookies; opt; opt = next) {
			next = opt->next;

			free(opt->option);
			free(opt->value);
			free(opt);
		}
		vpninfo->cookies = NULL;
		return OC_FORM_RESULT_OK;
	}
	if (!form->opts) {
		if (form->u.message)
			vpn_progress(vpninfo, PRG_INFO, "%s\n", form->u.message);
		if (form->u.error)
			vpn_progress(vpninfo, PRG_ERR, "%s\n", form->u.error);
		return -EPERM;
	}

	ret = process_auth_form(vpninfo, form);
	if (ret)
		return ret;

	/* tokencode generation is deferred until after username prompts and CSD */
	ret = do_gen_tokencode(vpninfo, form);
	if (ret)
		return ret;

	ret = vpninfo->xmlpost ?
	      xmlpost_append_form_opts(vpninfo, form, request_body, req_len) :
	      append_form_opts(vpninfo, form, request_body, req_len);
	if (!ret) {
		*method = "POST";
		*request_body_type = "application/x-www-form-urlencoded";
	}
	return ret;
}

void free_auth_form(struct __oc_auth_form *form)
{
	if (!form)
		return;
	while (form->opts) {
		struct __oc_form_opt *tmp = form->opts->next;
		if (form->opts->u.type == OC_FORM_OPT_TEXT ||
		    form->opts->u.type == OC_FORM_OPT_PASSWORD ||
		    form->opts->u.type == OC_FORM_OPT_HIDDEN ||
		    form->opts->u.type == OC_FORM_OPT_TOKEN)
			free(form->opts->u.value);
		else if (form->opts->u.type == OC_FORM_OPT_SELECT) {
			struct __oc_form_opt_select *sel = (void *)form->opts;
			int i;

			for (i = 0; i < sel->nr_choices; i++) {
				free(sel->choices[i].u.name);
				free(sel->choices[i].u.label);
				free(sel->choices[i].u.auth_type);
				free(sel->choices[i].u.override_name);
				free(sel->choices[i].u.override_label);
			}
		}
		free(form->opts->u.label);
		free(form->opts->u.name);
		free(form->opts);
		form->opts = tmp;
	}
	free(form->u.error);
	free(form->u.message);
	free(form->u.banner);
	free(form->u.auth_id);
	free(form->u.method);
	free(form->u.action);
	free(form);
}

/*
 * Old submission format is just an HTTP query string:
 *
 * password=12345678&username=joe
 *
 * New XML format is more complicated:
 *
 * <config-auth client="vpn" type="<!-- init or auth-reply -->">
 *   <version who="vpn"><!-- currently just the OpenConnect version --></version>
 *   <device-id><!-- linux, linux-64, mac, win --></device-id>
 *   <opaque is-for="<!-- some name -->">
 *     <!-- just copy this verbatim from whatever the gateway sent us -->
 *   </opaque>
 *
 * For init only, add:
 *   <group-access>https://<!-- insert hostname here --></group-access>
 *
 * For auth-reply only, add:
 *   <auth>
 *     <username><!-- same treatment as the old form options --></username>
 *     <password><!-- ditto -->
 *   </auth>
 *   <group-select><!-- name of selected authgroup --></group-select>
 *   <host-scan-token><!-- vpninfo->csd_ticket --></host-scan-token>
 */

#define XCAST(x) ((const xmlChar *)(x))

static xmlDocPtr xmlpost_new_query(struct openconnect_info *vpninfo, const char *type,
				   xmlNodePtr *rootp)
{
	xmlDocPtr doc;
	xmlNodePtr root, node;

	doc = xmlNewDoc(XCAST("1.0"));
	if (!doc)
		return NULL;

	*rootp = root = xmlNewNode(NULL, XCAST("config-auth"));
	if (!root)
		goto bad;
	if (!xmlNewProp(root, XCAST("client"), XCAST("vpn")))
		goto bad;
	if (!xmlNewProp(root, XCAST("type"), XCAST(type)))
		goto bad;
	xmlDocSetRootElement(doc, root);

	node = xmlNewTextChild(root, NULL, XCAST("version"), XCAST(openconnect_version_str));
	if (!node)
		goto bad;
	if (!xmlNewProp(node, XCAST("who"), XCAST("vpn")))
		goto bad;

	node = xmlNewTextChild(root, NULL, XCAST("device-id"), XCAST(vpninfo->platname));
	if (!node)
		goto bad;
	if (vpninfo->mobile_platform_version) {
		if (!xmlNewProp(node, XCAST("platform-version"), XCAST(vpninfo->mobile_platform_version)) ||
		    !xmlNewProp(node, XCAST("device-type"), XCAST(vpninfo->mobile_device_type)) ||
		    !xmlNewProp(node, XCAST("unique-id"), XCAST(vpninfo->mobile_device_uniqueid)))
			goto bad;
	}

	return doc;

bad:
	xmlFreeDoc(doc);
	return NULL;
}

static int xmlpost_complete(xmlDocPtr doc, char *body, int bodylen)
{
	xmlChar *mem = NULL;
	int len, ret = 0;

	if (!body) {
		xmlFree(doc);
		return 0;
	}

	xmlDocDumpMemoryEnc(doc, &mem, &len, "UTF-8");
	if (!mem) {
		xmlFreeDoc(doc);
		return -ENOMEM;
	}

	if (len > bodylen)
		ret = -E2BIG;
	else {
		memcpy(body, mem, len);
		body[len] = 0;
	}

	xmlFreeDoc(doc);
	xmlFree(mem);

	return ret;
}

int xmlpost_initial_req(struct openconnect_info *vpninfo, char *request_body, int req_len, int cert_fail)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "init", &root);
	char *url;
	int result;

	if (!doc)
		return -ENOMEM;

	if (vpninfo->urlpath)
		result = asprintf(&url, "https://%s/%s", vpninfo->hostname, vpninfo->urlpath);
	else
		result = asprintf(&url, "https://%s", vpninfo->hostname);

	if (result == -1)
		goto bad;
	node = xmlNewTextChild(root, NULL, XCAST("group-access"), XCAST(url));
	free(url);
	if (!node)
		goto bad;
	if (cert_fail) {
		node = xmlNewTextChild(root, NULL, XCAST("client-cert-fail"), NULL);
		if (!node)
			goto bad;
	}
	if (vpninfo->authgroup) {
		node = xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(vpninfo->authgroup));
		if (!node)
			goto bad;
	}
	return xmlpost_complete(doc, request_body, req_len);

bad:
	xmlpost_complete(doc, NULL, 0);
	return -ENOMEM;
}

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct __oc_auth_form *form, char *body, int bodylen)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "auth-reply", &root);
	struct __oc_form_opt *opt;

	if (!doc)
		return -ENOMEM;

	if (vpninfo->opaque_srvdata) {
		node = xmlCopyNode(vpninfo->opaque_srvdata, 1);
		if (!node)
			goto bad;
		if (!xmlAddChild(root, node))
			goto bad;
	}

	node = xmlNewChild(root, NULL, XCAST("auth"), NULL);
	if (!node)
		goto bad;

	for (opt = form->opts; opt; opt = opt->next) {
		/* group_list: create a new <group-select> node under <config-auth> */
		if (!strcmp(opt->u.name, "group_list")) {
			if (!xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(opt->u.value)))
				goto bad;
			continue;
		}

		/* answer,whichpin,new_password: rename to "password" */
		if (!strcmp(opt->u.name, "answer") ||
		    !strcmp(opt->u.name, "whichpin") ||
		    !strcmp(opt->u.name, "new_password")) {
			if (!xmlNewTextChild(node, NULL, XCAST("password"), XCAST(opt->u.value)))
				goto bad;
			continue;
		}

		/* verify_pin,verify_password: ignore */
		if (!strcmp(opt->u.name, "verify_pin") ||
		    !strcmp(opt->u.name, "verify_password")) {
			continue;
		}

		/* everything else: create <foo>user_input</foo> under <auth> */
		if (!xmlNewTextChild(node, NULL, XCAST(opt->u.name), XCAST(opt->u.value)))
			goto bad;
	}

	if (vpninfo->csd_token &&
	    !xmlNewTextChild(root, NULL, XCAST("host-scan-token"), XCAST(vpninfo->csd_token)))
		goto bad;

	return xmlpost_complete(doc, body, bodylen);

bad:
	xmlpost_complete(doc, NULL, 0);
	return -ENOMEM;
}


#ifdef HAVE_LIBSTOKEN
static void nuke_opt_values(struct __oc_form_opt *opt)
{
	for (; opt; opt = opt->next) {
		free(opt->u.value);
		opt->u.value = NULL;
	}
}
#endif

/*
 * If the user clicks OK without entering any data, we will continue
 * connecting but bypass soft token generation for the duration of
 * this "obtain_cookie" session.
 *
 * If the user clicks Cancel, we will abort the connection.
 *
 * Return value:
 *  < 0, on error
 *  = 0, on success (or if the user bypassed soft token init)
 *  = 1, if the user cancelled the form submission
 */
int prepare_stoken(struct openconnect_info *vpninfo)
{
#ifdef HAVE_LIBSTOKEN
	struct __oc_auth_form form;
	struct __oc_form_opt opts[3], *opt = opts;
	char **devid = NULL, **pass = NULL, **pin = NULL;
	int ret = 0;

	memset(&form, 0, sizeof(form));
	memset(&opts, 0, sizeof(opts));

	form.opts = opts;
	form.u.message = (char *)_("Enter credentials to unlock software token.");

	vpninfo->token_tries = 0;
	vpninfo->token_bypassed = 0;

	if (stoken_devid_required(vpninfo->stoken_ctx)) {
		opt->u.type = OC_FORM_OPT_TEXT;
		opt->u.name = (char *)"devid";
		opt->u.label = (char *)_("Device ID:");
		devid = &opt->u.value;
		opt++;
	}
	if (stoken_pass_required(vpninfo->stoken_ctx)) {
		opt->u.type = OC_FORM_OPT_PASSWORD;
		opt->u.name = (char *)"password";
		opt->u.label = (char *)_("Password:");
		pass = &opt->u.value;
		opt++;
	}
	if (stoken_pin_required(vpninfo->stoken_ctx)) {
		opt->u.type = OC_FORM_OPT_PASSWORD;
		opt->u.name = (char *)"password";
		opt->u.label = (char *)_("PIN:");
		pin = &opt->u.value;
		opt++;
	}

	opts[0].next = opts[1].u.type ? &opts[1] : NULL;
	opts[1].next = opts[2].u.type ? &opts[2] : NULL;

	while (1) {
		nuke_opt_values(opts);

		if (!opts[0].u.type) {
			/* don't bug the user if there's nothing to enter */
			ret = 0;
		} else {
			int some_empty = 0, all_empty = 1;

			/* < 0 for error; 1 if cancelled */
			ret = process_auth_form(vpninfo, &form);
			if (ret)
				break;

			for (opt = opts; opt; opt = opt->next) {
				if (!opt->u.value || !strlen(opt->u.value))
					some_empty = 1;
				else
					all_empty = 0;
			}
			if (all_empty) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("User bypassed soft token.\n"));
				vpninfo->token_bypassed = 1;
				ret = 0;
				break;
			}
			if (some_empty) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("All fields are required; try again.\n"));
				continue;
			}
		}

		ret = stoken_decrypt_seed(vpninfo->stoken_ctx,
					  pass ? *pass : NULL,
					  devid ? *devid : NULL);
		if (ret == -EIO || (ret && !devid && !pass)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("General failure in libstoken.\n"));
			break;
		} else if (ret != 0) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Incorrect device ID or password; try again.\n"));
			continue;
		}

		if (pin) {
			if (stoken_check_pin(vpninfo->stoken_ctx, *pin) != 0) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("Invalid PIN format; try again.\n"));
				continue;
			}
			free(vpninfo->stoken_pin);
			vpninfo->stoken_pin = strdup(*pin);
			if (!vpninfo->stoken_pin) {
				ret = -ENOMEM;
				break;
			}
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Soft token init was successful.\n"));
		ret = 0;
		break;
	}

	nuke_opt_values(opts);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int can_gen_stoken_code(struct openconnect_info *vpninfo,
			       struct __oc_auth_form *form,
			       struct __oc_form_opt *opt)
{
#ifdef HAVE_LIBSTOKEN
	if ((strcmp(opt->u.name, "password") && strcmp(opt->u.name, "answer")) ||
	    vpninfo->token_bypassed)
		return -EINVAL;
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
		vpninfo->token_time = 0;
	} else if (vpninfo->token_tries == 1 && form->u.message &&
		   strcasestr(form->u.message, "next tokencode")) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
		vpninfo->token_time += 60;
	} else {
		/* limit the number of retries, to avoid account lockouts */
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server is rejecting the soft token; switching to manual entry\n"));
		return -ENOENT;
	}
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int can_gen_totp_code(struct openconnect_info *vpninfo,
			     struct __oc_auth_form *form,
			     struct __oc_form_opt *opt)
{
#ifdef HAVE_LIBOATH
	if ((strcmp(opt->u.name, "secondary_password") != 0) ||
	    vpninfo->token_bypassed)
		return -EINVAL;
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
		vpninfo->token_time = 0;
	} else if (vpninfo->token_tries == 1) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
		vpninfo->token_time += OATH_TOTP_DEFAULT_TIME_STEP_SIZE;
	} else {
		/* limit the number of retries, to avoid account lockouts */
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server is rejecting the soft token; switching to manual entry\n"));
		return -ENOENT;
	}
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int can_gen_tokencode(struct openconnect_info *vpninfo,
			     struct __oc_auth_form *form,
			     struct __oc_form_opt *opt)
{
	switch (vpninfo->token_mode) {
	case OC_TOKEN_MODE_STOKEN:
		return can_gen_stoken_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_TOTP:
		return can_gen_totp_code(vpninfo, form, opt);

	default:
		return -EINVAL;
	}
}

static int do_gen_stoken_code(struct openconnect_info *vpninfo,
			      struct __oc_auth_form *form,
			      struct __oc_form_opt *opt)
{
#ifdef HAVE_LIBSTOKEN
	char tokencode[STOKEN_MAX_TOKENCODE + 1];

	if (!vpninfo->token_time)
		vpninfo->token_time = time(NULL);
	vpn_progress(vpninfo, PRG_INFO, _("Generating RSA token code\n"));

	/* This doesn't normally fail */
	if (stoken_compute_tokencode(vpninfo->stoken_ctx, vpninfo->token_time,
				     vpninfo->stoken_pin, tokencode) < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("General failure in libstoken.\n"));
		return -EIO;
	}

	vpninfo->token_tries++;
	opt->u.value = strdup(tokencode);
	return opt->u.value ? 0 : -ENOMEM;
#else
	return 0;
#endif
}

static int do_gen_totp_code(struct openconnect_info *vpninfo,
			    struct __oc_auth_form *form,
			    struct __oc_form_opt *opt)
{
#ifdef HAVE_LIBOATH
	int oath_err;
	char tokencode[7];

	if (!vpninfo->token_time)
		vpninfo->token_time = time(NULL);

	vpn_progress(vpninfo, PRG_INFO, _("Generating OATH TOTP token code\n"));

	oath_err = oath_totp_generate(vpninfo->oath_secret,
				      vpninfo->oath_secret_len,
				      vpninfo->token_time,
				      OATH_TOTP_DEFAULT_TIME_STEP_SIZE,
				      OATH_TOTP_DEFAULT_START_TIME,
				      6, tokencode);
	if (oath_err != OATH_OK) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unable to generate OATH TOTP token code: %s\n"),
			     oath_strerror(oath_err));
		return -EIO;
	}

	vpninfo->token_tries++;
	opt->u.value = strdup(tokencode);
	return opt->u.value ? 0 : -ENOMEM;
#else
	return 0;
#endif
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int do_gen_tokencode(struct openconnect_info *vpninfo,
			    struct __oc_auth_form *form)
{
	struct __oc_form_opt *opt;

	for (opt = form->opts; ; opt = opt->next) {
		/* this form might not have anything for us to do */
		if (!opt)
			return 0;
		if (opt->u.type == OC_FORM_OPT_TOKEN)
			break;
	}

	switch (vpninfo->token_mode) {
	case OC_TOKEN_MODE_STOKEN:
		return do_gen_stoken_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_TOTP:
		return do_gen_totp_code(vpninfo, form, opt);

	default:
		return -EINVAL;
	}
}
