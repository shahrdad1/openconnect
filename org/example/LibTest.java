/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2013 Kevin Cernekee <cernekee@gmail.com>
 *
 * Sample Java library client - usage:
 *
 *   ./configure --with-jni
 *   make
 *   javac org/example/LibTest.java
 *   java -Djava.library.path=.libs org.example.LibTest <server_ip>
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

package org.example;

import java.io.*;
import org.infradead.openconnect.LibOpenConnect;

public final class LibTest {
	private static String getline() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			String line = br.readLine();
			return line;
		} catch (IOException e) {
			System.out.println("\nI/O error");
			System.exit(1);
		}
		return "";
	}

	private static class TestLib extends LibOpenConnect {
		public int onValidatePeerCert(String msg) {
			System.out.println("cert warning: " + msg);
			System.out.println("cert SHA1: " + getCertSHA1());
			System.out.println("cert details: " + getCertDetails());

			byte der[] = getCertDER();
			System.out.println("DER is " + der.length + " bytes long");

			System.out.print("\nAccept this certificate? [n] ");
			String s = getline();
			if (s.startsWith("y") || s.startsWith("Y")) {
				return 0;
			} else {
				return -1;
			}
		}

		public int onWriteNewConfig(byte[] buf) {
			System.out.println("new config: " + buf.length + " bytes");
			return 0;
		}

		public int onProcessAuthForm(LibOpenConnect.AuthForm authForm) {
			System.out.println("AuthForm:");
			System.out.println("+-banner: " + authForm.banner);
			System.out.println("+-message: " + authForm.message);
			System.out.println("+-error: " + authForm.error);
			System.out.println("+-authID: " + authForm.authID);
			System.out.println("+-method: " + authForm.method);
			System.out.println("+-action: " + authForm.action);

			for (FormOpt fo : authForm.opts) {
				System.out.println("->FormOpt: ");
				System.out.println("  +-type: " + fo.type);
				System.out.println("  +-name: " + fo.name);
				System.out.println("  +-label: " + fo.label);

				if (fo.type == OC_FORM_OPT_SELECT) {
					for (FormChoice fc : fo.choices) {
						System.out.println("--->FormChoice: ");
						System.out.println("    +-name: " + fc.name);
						System.out.println("    +-label: " + fc.label);
						System.out.println("    +-authType: " + fc.authType);
						System.out.println("    +-overrideName: " + fc.overrideName);
						System.out.println("    +-overrideLabel: " + fc.overrideLabel);
					}
				}

				if (fo.type == OC_FORM_OPT_TEXT ||
				    fo.type == OC_FORM_OPT_PASSWORD ||
				    fo.type == OC_FORM_OPT_SELECT) {
					System.out.print("\n" + fo.label);
					fo.setValue(getline());
				}
			}

			return AUTH_FORM_PARSED;
		}

		public void onProgress(int level, String msg) {
			System.out.print("progress: level " + level + ", msg " + msg);
		}
	}

	public static void main(String argv[]) {
		System.loadLibrary("openconnect");
		LibOpenConnect lib = new TestLib();

		if (argv.length != 1) {
			System.out.println("usage: LibTest <server_name>");
			System.exit(1);
		}

		System.out.println("OpenConnect version: " + lib.getVersion());
		System.out.println("  PKCS=" + lib.hasPKCS11Support() +
				   ", TSS=" + lib.hasTSSBlobSupport() +
				   ", STOKEN=" + lib.hasStokenSupport() +
				   ", OATH=" + lib.hasOATHSupport());
		lib.setReportedOS("win");
		//lib.setTokenMode(LibOpenConnect.OC_TOKEN_MODE_STOKEN, null);
		if (new File("/tmp/csd.sh").exists()) {
			lib.setCSDWrapper("/tmp/csd.sh");
		}
		lib.parseURL(argv[0]);

		int ret = lib.obtainCookie();
		if (ret < 0) {
			System.out.println("obtainCookie() returned error");
		} else if (ret > 0) {
			System.out.println("Aborted by user");
		} else {
			System.out.println("urlpath: " + lib.getUrlpath());
			System.out.println("hostname: " + lib.getHostname());
			System.out.println("cookie: " + lib.getCookie());
		}
	}
}
