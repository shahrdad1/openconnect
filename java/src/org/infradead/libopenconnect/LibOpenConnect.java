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

package org.infradead.libopenconnect;

import java.util.ArrayList;

public abstract class LibOpenConnect {

	/* constants */

	public static final int AUTH_FORM_ERROR = -1;
	public static final int AUTH_FORM_PARSED = 0;
	public static final int AUTH_FORM_CANCELLED = 1;

	public static final int OC_FORM_OPT_TEXT = 1;
	public static final int OC_FORM_OPT_PASSWORD = 2;
	public static final int OC_FORM_OPT_SELECT = 3;
	public static final int OC_FORM_OPT_HIDDEN = 4;
	public static final int OC_FORM_OPT_TOKEN = 5;

	public static final int OC_TOKEN_MODE_NONE = 0;
	public static final int OC_TOKEN_MODE_STOKEN = 1;
	public static final int OC_TOKEN_MODE_TOTP = 2;

	public static final int PRG_ERR = 0;
	public static final int PRG_INFO = 1;
	public static final int PRG_DEBUG = 2;
	public static final int PRG_TRACE = 3;

	/* required callbacks */

	public abstract int onValidatePeerCert(String msg);
	public abstract int onWriteNewConfig(byte[] buf);
	public abstract int onProcessAuthForm(AuthForm authForm);
	public abstract void onProgress(int level, String msg);

	/* create/destroy library instances */

	public LibOpenConnect() {
		libctx = init("OpenConnect VPN Agent (Java)");
	}

	public synchronized void destroy() {
		if (libctx != 0) {
			free();
			libctx = 0;
		}
	}

	public void cancel() {
		synchronized (cancelLock) {
			if (!canceled) {
				doCancel();
				canceled = true;
			}
		}
	}

	public boolean isCanceled() {
		synchronized (cancelLock) {
			return canceled;
		}
	}

	/* control operations */

	public synchronized native int parseURL(String url);
	public synchronized native int obtainCookie();
	public synchronized native void clearCookie();
	public synchronized native void resetSSL();
	public synchronized native int makeCSTPConnection();
	public synchronized native int setupTunDevice(String vpncScript, String IFName);
	public synchronized native int setupTunScript(String tunScript);
	public synchronized native int setupTunFD(int tunFD);
	public synchronized native int setupDTLS(int attemptPeriod);
	public synchronized native int mainloop();

	/* connection settings */

	public synchronized native void setLogLevel(int level);
	public synchronized native int passphraseFromFSID();
	public synchronized native void setCertExpiryWarning(int seconds);
	public synchronized native int setHTTPProxy(String proxy);
	public synchronized native void setXMLSHA1(String hash);
	public synchronized native void setHostname(String hostname);
	public synchronized native void setUrlpath(String urlpath);
	public synchronized native void setCAFile(String caFile);
	public synchronized native void setReportedOS(String os);
	public synchronized native int setTokenMode(int tokenMode, String tokenString);
	public synchronized native void setCSDWrapper(String wrapper);
	public synchronized native void setClientCert(String cert, String sslKey);
	public synchronized native void setServerCertSHA1(String hash);
	public synchronized native void setReqMTU(int mtu);

	/* connection info */

	public synchronized native String getHostname();
	public synchronized native String getUrlpath();
	public synchronized native int getPort();
	public synchronized native String getCookie();
	public synchronized native String getIFName();
	public synchronized native IPInfo getIPInfo();

	/* certificate info */

	public synchronized native String getCertSHA1();
	public synchronized native String getCertDetails();
	public synchronized native byte[] getCertDER();

	/* library info */

	public static native String getVersion();
	public static native boolean hasPKCS11Support();
	public static native boolean hasTSSBlobSupport();
	public static native boolean hasStokenSupport();
	public static native boolean hasOATHSupport();

	/* public data structures */

	public static class FormOpt {
		public int type;
		public String name;
		public String label;
		public ArrayList<FormChoice> choices = new ArrayList<FormChoice>();
		String value;

		public void setValue(String value) {
			this.value = value;
		}

		/* FormOpt internals (called from JNI) */

		void addChoice(FormChoice fc) {
			this.choices.add(fc);
		}
	};

	public static class FormChoice {
		public String name;
		public String label;
		public String authType;
		public String overrideName;
		public String overrideLabel;
	};

	public static class AuthForm {
		public String banner;
		public String message;
		public String error;
		public String authID;
		public String method;
		public String action;
		public ArrayList<FormOpt> opts = new ArrayList<FormOpt>();

		/* AuthForm internals (called from JNI) */

		FormOpt addOpt() {
			FormOpt fo = new FormOpt();
			opts.add(fo);
			return fo;
		}

		String getOptValue(String name) {
			for (FormOpt fo : opts) {
				if (fo.name.equals(name)) {
					return fo.value;
				}
			}
			return null;
		}
	}

	public static class IPInfo {
		public String addr;
		public String netmask;
		public String addr6;
		public String netmask6;
		public ArrayList<String> DNS = new ArrayList<String>();
		public ArrayList<String> NBNS = new ArrayList<String>();
		public String domain;
		public String proxyPac;
		public int MTU;

		public ArrayList<String> splitDNS = new ArrayList<String>();
		public ArrayList<String> splitIncludes = new ArrayList<String>();
		public ArrayList<String> splitExcludes = new ArrayList<String>();

		/* IPInfo internals (called from JNI) */

		void addDNS(String arg) { DNS.add(arg); }
		void addNBNS(String arg) { NBNS.add(arg); }
		void addSplitDNS(String arg) { splitDNS.add(arg); }
		void addSplitInclude(String arg) { splitIncludes.add(arg); }
		void addSplitExclude(String arg) { splitExcludes.add(arg); }
	}

	/* LibOpenConnect internals */

	long libctx;
	boolean canceled = false;
	Object cancelLock = new Object();

	static synchronized native void globalInit();
	static {
		globalInit();
	}

	synchronized native long init(String useragent);
	synchronized native void free();
	native void doCancel();
}
