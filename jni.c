/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2013 Kevin Cernekee <cernekee@gmail.com>
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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <jni.h>
#include "openconnect.h"

struct libctx {
	JNIEnv *jenv;
	jobject jobj;
	struct openconnect_info *vpninfo;
	OPENCONNECT_X509 *cert;
	int pipefd[2];
};

JNIEXPORT jlong JNICALL Java_org_infradead_openconnect_LibOpenConnect_init(
	JNIEnv *jenv, jobject jobj, jstring juseragent);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_free(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_cancel(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_globalInit(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_parseURL(
	JNIEnv *jenv, jobject jobj, jstring jurl);
JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_obtainCookie(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertSHA1(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertDetails(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jbyteArray JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertDER(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setClientCert(
	JNIEnv *jenv, jobject jobj, jstring jcert, jstring jsslkey);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getVersion(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasPKCS11Support(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasTSSBlobSupport(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasStokenSupport(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasOATHSupport(
	JNIEnv *jenv, jclass jcls);
JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_getPort(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_passphraseFromFSID(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_clearCookie(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_resetSSL(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCertExpiryWarning(
	JNIEnv *jenv, jobject jobj, jint seconds);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getHostname(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getUrlpath(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCookie(
	JNIEnv *jenv, jobject jobj);
JNIEXPORT int JNICALL Java_org_infradead_openconnect_LibOpenConnect_setHTTPProxy(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setXMLSHA1(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setHostname(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setUrlpath(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCAFile(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setReportedOS(
	JNIEnv *jenv, jobject jobj, jstring jarg);
JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_setTokenMode(
	JNIEnv *jenv, jobject jobj, jint mode, jstring jarg);
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCSDWrapper(
	JNIEnv *jenv, jobject jobj, jstring jarg);

static void throw_excep(JNIEnv *jenv, const char *exc, int line)
{
	jclass excep;
	char msg[64];

	snprintf(msg, 64, "%s:%d", __FILE__, line);

	(*jenv)->ExceptionClear(jenv);
	excep = (*jenv)->FindClass(jenv, exc);
	if (excep)
		(*jenv)->ThrowNew(jenv, excep, msg);
}

#define OOM(jenv)	do { throw_excep(jenv, "java/lang/OutOfMemoryError", __LINE__); } while (0)

/*
 * jobj (a reference to the LibOpenConnect object) isn't always guaranteed to
 * stay constant across nested calls.  e.g.
 * for obtainCookie() -> onValidatePeerCert() -> getCertSHA1(), different
 * jobj values could be supplied to obtainCookie() and getCertSHA1().
 *
 * We want our callbacks to always use the jenv/jobj values supplied by the
 * Java caller, so we save and restore the values in each native function.
 *
 * None of this is the slightest bit thread-safe.
 */
#define PUSH_CTX(err_retval...) do { \
	ctx = getctx(jenv, jobj); \
	if (!ctx) \
		return err_retval; \
	oldctx.jenv = ctx->jenv; \
	oldctx.jobj = ctx->jobj; \
	ctx->jenv = jenv; \
	ctx->jobj = jobj; \
} while (0)

#define POP_CTX() do { \
	ctx->jenv = oldctx.jenv; \
	ctx->jobj = oldctx.jobj; \
} while (0)

static struct libctx *getctx(JNIEnv *jenv, jobject jobj)
{
	jclass jcls = (*jenv)->GetObjectClass(jenv, jobj);
	jfieldID jfld = (*jenv)->GetFieldID(jenv, jcls, "libctx", "J");
	if (!jfld)
		return NULL;
	return (void *)(*jenv)->GetLongField(jenv, jobj, jfld);
}

/*
 * GetMethodID() and GetFieldID() and NewStringUTF() will automatically throw exceptions on error
 */
static jmethodID get_obj_mid(struct libctx *ctx, jobject jobj, const char *name, const char *sig)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, jobj);
	jmethodID mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, name, sig);
	return mid;
}

static jstring dup_to_jstring(JNIEnv *jenv, const char *in)
{
	/*
	 * Many implementations of NewStringUTF() will return NULL on
	 * NULL input, but that isn't guaranteed:
	 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=35979
	 */
	return in ? (*jenv)->NewStringUTF(jenv, in) : NULL;
}

static int dup_to_cstring(JNIEnv *jenv, jstring in, char **out)
{
	const char *tmp;

	if (in == NULL) {
		*out = NULL;
		return 0;
	}

	tmp = (*jenv)->GetStringUTFChars(jenv, in, NULL);
	if (!tmp) {
		OOM(jenv);
		return -1;
	}

	*out = strdup(tmp);
	(*jenv)->ReleaseStringUTFChars(jenv, in, tmp);

	if (!*out) {
		OOM(jenv);
		return -1;
	}
	return 0;
}

static int set_string(struct libctx *ctx, jclass jcls, jobject jobj,
		      const char *name, const char *value)
{
	jmethodID mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, name, "(Ljava/lang/String;)V");
	jstring jarg;

	if (!value)
		return 0;

	if (!mid)
		return -1;
	jarg = dup_to_jstring(ctx->jenv, value);
	if (!jarg)
		return -1;

	(*ctx->jenv)->CallVoidMethod(ctx->jenv, jobj, mid, jarg);
	(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jarg, NULL);

	return 0;
}

static int validate_peer_cert_cb(void *privdata, OPENCONNECT_X509 *cert, const char *reason)
{
	struct libctx *ctx = privdata;
	jstring jreason;
	int ret = -1;
	jmethodID mid;

	jreason = dup_to_jstring(ctx->jenv, reason);
	if (!jreason)
		return -1;

	ctx->cert = cert;
	mid = get_obj_mid(ctx, ctx->jobj, "onValidatePeerCert", "(Ljava/lang/String;)I");
	if (mid)
		ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, mid, jreason);
	(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jreason, NULL);

	return ret;
}

static int write_new_config_cb(void *privdata, char *buf, int buflen)
{
	struct libctx *ctx = privdata;
	jmethodID mid;
	jbyteArray jbuf;
	int ret = -1;

	mid = get_obj_mid(ctx, ctx->jobj, "onWriteNewConfig", "([B)I");
	if (!mid)
		goto out;

	jbuf = (*ctx->jenv)->NewByteArray(ctx->jenv, buflen);
	if (!jbuf)
		goto out;
	(*ctx->jenv)->SetByteArrayRegion(ctx->jenv, jbuf, 0, buflen, (jbyte *)buf);

	ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, mid, jbuf);
	(*ctx->jenv)->ReleaseByteArrayElements(ctx->jenv, jbuf, NULL, 0);

out:
	return ret;
}

static jobject new_auth_form(struct libctx *ctx, struct oc_auth_form *form)
{
	jmethodID mid;
	jclass jcls;
	jobject jobj = NULL;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv, "org/infradead/openconnect/LibOpenConnect$AuthForm");
	if (jcls == NULL)
		return NULL;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		return NULL;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		return NULL;

	if (set_string(ctx, jcls, jobj, "setBanner", form->banner) ||
	    set_string(ctx, jcls, jobj, "setMessage", form->message) ||
	    set_string(ctx, jcls, jobj, "setError", form->error) ||
	    set_string(ctx, jcls, jobj, "setAuthID", form->auth_id) ||
	    set_string(ctx, jcls, jobj, "setMethod", form->method) ||
	    set_string(ctx, jcls, jobj, "setAction", form->action)) {
		return NULL;
	}

	return jobj;
}

static jobject new_form_choice(struct libctx *ctx, struct oc_choice *choice)
{
	jmethodID mid;
	jclass jcls;
	jobject jobj = NULL;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv,
				       "org/infradead/openconnect/LibOpenConnect$FormChoice");
	if (jcls == NULL)
		return NULL;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		return NULL;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		return NULL;

	if (set_string(ctx, jcls, jobj, "setName", choice->name) ||
	    set_string(ctx, jcls, jobj, "setLabel", choice->label) ||
	    set_string(ctx, jcls, jobj, "setAuthType", choice->auth_type) ||
	    set_string(ctx, jcls, jobj, "setOverrideName", choice->override_name) ||
	    set_string(ctx, jcls, jobj, "setOverrideLabel", choice->override_label)) {
		return NULL;
	}

	return jobj;
}

static int populate_select_choices(struct libctx *ctx, jobject jopt, struct oc_form_opt_select *opt)
{
	jmethodID mid;
	int i;

	mid = get_obj_mid(ctx, jopt, "addChoice",
			  "(Lorg/infradead/openconnect/LibOpenConnect$FormChoice;)V");
	if (!mid)
		return -1;

	for (i = 0; i < opt->nr_choices; i++) {
		jobject jformchoice = new_form_choice(ctx, &opt->choices[i]);
		if (!jformchoice)
			return -1;
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, jopt, mid, jformchoice);
	}
	return 0;
}

static int add_form_option(struct libctx *ctx, jobject jform, struct oc_form_opt *opt)
{
	jmethodID addOpt;
	jstring jname = NULL, jlabel = NULL;
	jobject jopt;
	int ret = -1;

	addOpt = get_obj_mid(ctx, jform, "addOpt",
		"(ILjava/lang/String;Ljava/lang/String;)Lorg/infradead/openconnect/LibOpenConnect$FormOpt;");
	if (!addOpt)
		goto out;

	if (opt->name) {
		jname = dup_to_jstring(ctx->jenv, opt->name);
		if (!jname)
			goto out;
	}

	if (opt->label) {
		jlabel = dup_to_jstring(ctx->jenv, opt->label);
		if (!jlabel)
			goto out;
	}

	jopt = (*ctx->jenv)->CallObjectMethod(ctx->jenv, jform, addOpt, opt->type, jname, jlabel);

	if (opt->type == OC_FORM_OPT_SELECT &&
	    populate_select_choices(ctx, jopt, (struct oc_form_opt_select *)opt))
		ret = -1;
	else
		ret = 0;

out:
	if (jlabel)
		(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jlabel, NULL);
	if (jname)
		(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jname, NULL);
	return ret;
}

static int process_auth_form_cb(void *privdata, struct oc_auth_form *form)
{
	struct libctx *ctx = privdata;
	jobject jform;
	jmethodID callback, getOptValue;
	struct oc_form_opt *opt;
	jint ret;

	/* create and populate new AuthForm object and option/choice lists */

	jform = new_auth_form(ctx, form);
	if (!jform)
		return -1;

	getOptValue = get_obj_mid(ctx, jform, "getOptValue", "(Ljava/lang/String;)Ljava/lang/String;");
	if (!getOptValue)
		return -1;

	for (opt = form->opts; opt; opt = opt->next)
		if (add_form_option(ctx, jform, opt) < 0)
			return -1;

	/* invoke onProcessAuthForm callback */

	callback = get_obj_mid(ctx, ctx->jobj, "onProcessAuthForm",
			       "(Lorg/infradead/openconnect/LibOpenConnect$AuthForm;)I");
	if (!callback)
		return -1;

	ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, callback, jform);

	/* copy any populated form fields back into the C structs */

	for (opt = form->opts; opt; opt = opt->next) {
		jstring jname, jvalue;

		jname = dup_to_jstring(ctx->jenv, opt->name);
		if (!jname)
			return -1;

		jvalue = (*ctx->jenv)->CallObjectMethod(ctx->jenv, jform, getOptValue, jname);
		if (jvalue) {
			const char *tmp = (*ctx->jenv)->GetStringUTFChars(ctx->jenv, jvalue, NULL);
			if (!tmp) {
				(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jname, NULL);
				return -1;
			}
			opt->value = strdup(tmp);
			if (!opt->value)
				OOM(ctx->jenv);
			(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jvalue, tmp);
		}
		(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jname, NULL);
	}

	return ret;
}

static void progress_cb(void *privdata, int level, const char *fmt, ...)
{
	struct libctx *ctx = privdata;
	va_list ap;
	char *msg;
	jstring jmsg;
	int ret;
	jmethodID mid;

	va_start(ap, fmt);
	ret = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		OOM(ctx->jenv);
		return;
	}

	jmsg = dup_to_jstring(ctx->jenv, msg);
	free(msg);
	if (!jmsg)
		return;

	mid = get_obj_mid(ctx, ctx->jobj, "onProgress", "(ILjava/lang/String;)V");
	if (mid)
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, ctx->jobj, mid, level, jmsg);
	(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jmsg, NULL);
}

/* Library init/uninit */

JNIEXPORT jlong JNICALL Java_org_infradead_openconnect_LibOpenConnect_init(
	JNIEnv *jenv, jobject jobj, jstring juseragent)
{
	char *useragent;
	struct libctx *ctx = calloc(1, sizeof(*ctx));

	if (!ctx) {
		OOM(jenv);
		return 0;
	}

	if (pipe(ctx->pipefd) < 0) {
		throw_excep(jenv, "java/lang/IOException", __LINE__);
		free(ctx);
		return 0;
	}

	useragent = (char *)(*jenv)->GetStringUTFChars(jenv, juseragent, NULL);
	if (!useragent) {
		close(ctx->pipefd[0]);
		close(ctx->pipefd[1]);
		free(ctx);
		OOM(jenv);
		return 0;
	}
	ctx->vpninfo = openconnect_vpninfo_new(useragent, validate_peer_cert_cb,
					       write_new_config_cb, process_auth_form_cb,
					       progress_cb, ctx);
	openconnect_set_cancel_fd(ctx->vpninfo, ctx->pipefd[0]);
	(*jenv)->ReleaseStringUTFChars(jenv, juseragent, useragent);
	return (jlong) ctx;
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_free(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;

	PUSH_CTX();
	openconnect_vpninfo_free(ctx->vpninfo);
	close(ctx->pipefd[0]);
	close(ctx->pipefd[1]);
	free(ctx);
	POP_CTX();
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_cancel(
	JNIEnv *jenv, jobject jobj)
{
	/* This doesn't use PUSH_CTX so it is safe to call from another thread */
	struct libctx *ctx = getctx(jenv, jobj);
	char data = '.';

	if (write(ctx->pipefd[1], &data, 1) < 0) {
		throw_excep(jenv, "java/lang/IOException", __LINE__);
	}
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_globalInit(
	JNIEnv *jenv, jclass jcls)
{
	openconnect_init_ssl();
}

JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_parseURL(
	JNIEnv *jenv, jobject jobj, jstring jurl)
{
	struct libctx *ctx, oldctx;
	char *url;
	int ret = -1;

	PUSH_CTX(ret);
	url = (char *)(*jenv)->GetStringUTFChars(jenv, jurl, NULL);
	if (!url) {
		OOM(ctx->jenv);
	} else {
		ret = openconnect_parse_url(ctx->vpninfo, url);
		(*jenv)->ReleaseStringUTFChars(jenv, jurl, url);
	}

	POP_CTX();
	return ret;
}

JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_obtainCookie(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	int ret;

	PUSH_CTX(0);
	ctx->cert = NULL;
	ret = openconnect_obtain_cookie(ctx->vpninfo);
	if (ret == 0)
		ctx->cert = openconnect_get_peer_cert(ctx->vpninfo);
	POP_CTX();
	return ret;
}

/* special handling: caller-allocated buffer */
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertSHA1(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	char buf[41];
	jstring jresult = NULL;

	PUSH_CTX(NULL);
	if (!ctx->cert)
		goto out;
	if (openconnect_get_cert_sha1(ctx->vpninfo, ctx->cert, buf))
		goto out;
	jresult = dup_to_jstring(ctx->jenv, buf);
	if (!jresult)
		OOM(ctx->jenv);

out:
	POP_CTX();
	return jresult;
}

/* special handling: callee-allocated, caller-freed string */
JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertDetails(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	char *buf = NULL;
	jstring jresult = NULL;

	PUSH_CTX(NULL);
	if (!ctx->cert)
		goto out;
	buf = openconnect_get_cert_details(ctx->vpninfo, ctx->cert);
	if (!buf)
		goto out;

	jresult = dup_to_jstring(ctx->jenv, buf);
	if (!jresult)
		OOM(ctx->jenv);

out:
	free(buf);
	POP_CTX();
	return jresult;
}

/* special handling: callee-allocated, caller-freed binary buffer */
JNIEXPORT jbyteArray JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCertDER(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	unsigned char *buf = NULL;
	int ret;
	jbyteArray jresult = NULL;

	PUSH_CTX(NULL);
	if (!ctx->cert)
		goto out;
	ret = openconnect_get_cert_DER(ctx->vpninfo, ctx->cert, &buf);
	if (ret < 0)
		goto out;

	jresult = (*ctx->jenv)->NewByteArray(ctx->jenv, ret);
	if (!jresult)
		goto out;
	(*ctx->jenv)->SetByteArrayRegion(ctx->jenv, jresult, 0, ret, (jbyte *) buf);

out:
	free(buf);
	POP_CTX();
	return jresult;
}

/* special handling: two string arguments */
JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setClientCert(
	JNIEnv *jenv, jobject jobj, jstring jcert, jstring jsslkey)
{
	struct libctx *ctx, oldctx;
	char *cert = NULL, *sslkey = NULL;

	PUSH_CTX();
	if (dup_to_cstring(ctx->jenv, jcert, &cert) ||
	    dup_to_cstring(ctx->jenv, jsslkey, &sslkey)) {
		free(cert);
		free(sslkey);
		goto out;
	}

	openconnect_set_client_cert(ctx->vpninfo, cert, sslkey);

out:
	POP_CTX();
}

/* class methods (general library info) */

JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getVersion(
	JNIEnv *jenv, jclass jcls)
{
	return dup_to_jstring(jenv, openconnect_get_version());
}

JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasPKCS11Support(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_pkcs11_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasTSSBlobSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_tss_blob_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasStokenSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_stoken_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_openconnect_LibOpenConnect_hasOATHSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_oath_support();
}

/* simple cases: void or int params */

JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_getPort(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	int ret;

	PUSH_CTX(-EINVAL);
	ret = openconnect_get_port(ctx->vpninfo);
	POP_CTX();
	return ret;
}

JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_passphraseFromFSID(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;
	int ret;

	PUSH_CTX(-EINVAL);
	ret = openconnect_passphrase_from_fsid(ctx->vpninfo);
	POP_CTX();
	return ret;
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_clearCookie(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;

	PUSH_CTX();
	openconnect_clear_cookie(ctx->vpninfo);
	POP_CTX();
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_resetSSL(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx, oldctx;

	PUSH_CTX();
	openconnect_reset_ssl(ctx->vpninfo);
	POP_CTX();
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCertExpiryWarning(
	JNIEnv *jenv, jobject jobj, jint seconds)
{
	struct libctx *ctx, oldctx;

	PUSH_CTX();
	openconnect_set_cert_expiry_warning(ctx->vpninfo, seconds);
	POP_CTX();
}

/* simple cases: return a const string (no need to free it) */

#define RETURN_STRING_START \
	struct libctx *ctx, oldctx; \
	char *buf = NULL; \
	jstring jresult = NULL; \
	PUSH_CTX(NULL);

#define RETURN_STRING_END \
	if (!buf) \
		goto out; \
	jresult = dup_to_jstring(ctx->jenv, buf); \
	if (!jresult) \
		OOM(ctx->jenv); \
out: \
	POP_CTX(); \
	return jresult;

JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getHostname(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_hostname(ctx->vpninfo);
	RETURN_STRING_END
}

JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getUrlpath(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_urlpath(ctx->vpninfo);
	RETURN_STRING_END
}

JNIEXPORT jstring JNICALL Java_org_infradead_openconnect_LibOpenConnect_getCookie(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_cookie(ctx->vpninfo);
	RETURN_STRING_END
}

#define SET_STRING_START(ret) \
	struct libctx *ctx, oldctx; \
	char *arg; \
	PUSH_CTX(ret); \
	if (dup_to_cstring(ctx->jenv, jarg, &arg)) \
		return ret;

#define SET_STRING_END \
	POP_CTX();

JNIEXPORT int JNICALL Java_org_infradead_openconnect_LibOpenConnect_setHTTPProxy(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_set_http_proxy(ctx->vpninfo, arg);
	SET_STRING_END
	return ret;
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setXMLSHA1(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_xmlsha1(ctx->vpninfo, arg, strlen(arg) + 1);
	SET_STRING_END
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setHostname(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_hostname(ctx->vpninfo, arg);
	SET_STRING_END
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setUrlpath(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_urlpath(ctx->vpninfo, arg);
	SET_STRING_END
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCAFile(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_cafile(ctx->vpninfo, arg);
	SET_STRING_END
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setReportedOS(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_reported_os(ctx->vpninfo, arg);
	SET_STRING_END
}

JNIEXPORT jint JNICALL Java_org_infradead_openconnect_LibOpenConnect_setTokenMode(
	JNIEnv *jenv, jobject jobj, jint mode, jstring jarg)
{
	int ret;
	SET_STRING_START(-EINVAL)
	ret = openconnect_set_token_mode(ctx->vpninfo, mode, arg);
	free(arg);
	SET_STRING_END
	return ret;
}

JNIEXPORT void JNICALL Java_org_infradead_openconnect_LibOpenConnect_setCSDWrapper(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_setup_csd(ctx->vpninfo, getuid(), 1, arg);
	SET_STRING_END
}
