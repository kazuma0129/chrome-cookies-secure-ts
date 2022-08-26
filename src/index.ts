import sqlite3 from "sqlite3";
import tld from "tldjs";
import request from "request";
import url from "url";
import crypto from "crypto";
import keytar from "keytar";

import tough from "tough-cookie";

const KEYLENGTH = 16;
const SALT = "saltysalt";
let ITERATIONS = 0;

const decrypt = (key: crypto.CipherKey, encryptedData: string) => {
  const iv = Buffer.from(new Array(KEYLENGTH + 1).join(" "), "binary");

  let decipher: crypto.Decipher;
  decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);

  encryptedData = encryptedData.slice(3);

  let decoded = decipher.update(encryptedData, "utf-8");

  decipher.final().copy(decoded, decoded.length - 1);

  const padding = decoded[decoded.length - 1];
  if (padding) {
    decoded = decoded.slice(0, decoded.length - padding);
  }

  return decoded.toString("utf8");
};

const getDerivedKey = async (
  callback: (err: Error | null, derivedKey: Buffer) => void
) => {
  let chromePassword;
  if (process.platform === "darwin") {
    const cPass = await keytar.getPassword("Chrome Safe Storage", "Chrome");
    if (!cPass) {
      throw Error("password not found");
    }
    crypto.pbkdf2(cPass, SALT, ITERATIONS, KEYLENGTH, "sha1", callback);
  } else if (process.platform === "linux") {
    chromePassword = "peanuts";
    crypto.pbkdf2(
      chromePassword,
      SALT,
      ITERATIONS,
      KEYLENGTH,
      "sha1",
      callback
    );
  } else {
    throw Error("not supported os");
  }
};

const convertChromiumTimestampToUnix = (timestamp: string) => {
  return Math.floor(
    Number(
      (BigInt(timestamp) - BigInt("11644473600000000")) / BigInt("1000000")
    )
  );
};

type Cookie = {
  host_key?: string;
  domain?: string;
  path?: string;
  is_secure: boolean;
  is_httponly: boolean;
  has_expires: boolean;
  expires_utc: string;
  name: string;
  value: string;
  encrypted_value: string;
};

const convertRawToNetscapeCookieFileFormat = (
  cookies: Cookie[],
  domain: string
) => {
  let out = "";

  cookies.forEach((cookie, index) => {
    out += cookie.host_key + "\t";
    out += (cookie.host_key === "." + domain ? "TRUE" : "FALSE") + "\t";
    out += cookie.path + "\t";
    out += (cookie.is_secure ? "TRUE" : "FALSE") + "\t";

    if (cookie.has_expires === true) {
      out +=
        convertChromiumTimestampToUnix(cookie.expires_utc).toString() + "\t";
    } else {
      out += "0" + "\t";
    }

    out += cookie.name + "\t";
    out += cookie.value + "\t";

    if (cookies.length > index + 1) {
      out += "\n";
    }
  });

  return out;
};

const convertRawToHeader = (cookies: Cookie[]) => {
  let out = "";

  cookies.forEach((cookie, index) => {
    out += cookie.name + "=" + cookie.value;
    if (cookies.length > index + 1) {
      out += "; ";
    }
  });

  return out;
};

const convertRawToJar = (cookies: Cookie[], uri: string) => {
  const jar = request.jar();

  cookies.forEach((cookie) => {
    const jarCookie = request.cookie(cookie.name + "=" + cookie.value);
    if (jarCookie) {
      jar.setCookie(jarCookie, uri);
    }
  });

  return jar;
};

const convertRawToSetCookieStrings = (cookies: Cookie[]) => {
  const strings: string[] = [];

  cookies.forEach((cookie) => {
    let out = "";

    const dateExpires = new Date(
      convertChromiumTimestampToUnix(cookie.expires_utc) * 1000
    );

    out += cookie.name + "=" + cookie.value + "; ";
    out += "expires=" + tough.formatDate(dateExpires) + "; ";
    out += "domain=" + cookie.host_key + "; ";
    out += "path=" + cookie.path;

    if (cookie.is_secure) {
      out += "; Secure";
    }

    if (cookie.is_httponly) {
      out += "; HttpOnly";
    }

    strings.push(out);
  });

  return strings;
};

type PuppetterCookie = {
  name: string;
  value: string;
  expires: string;
  domain?: string;
  path?: string;
  Secure?: boolean;
  HttpOnly?: boolean;
};

const convertRawToPuppeteerState = (cookies: Cookie[]) => {
  const puppeteerCookies: PuppetterCookie[] = cookies.map((cookie) => ({
    name: cookie.name,
    value: cookie.value,
    expires: cookie.expires_utc,
    domain: cookie.host_key,
    path: cookie.path,
    Secure: cookie.is_secure,
    HttpOnly: cookie.is_httponly,
  }));

  return puppeteerCookies;
};

const convertRawToObject = (
  cookies: Cookie[]
): { [name: Cookie["name"]]: Cookie["value"] } => {
  return cookies.reduce((acc, c) => ({ ...acc, [c.name]: c.value }), {});
};

type Format =
  | "curl"
  | "jar"
  | "set"
  | "header"
  | "puppeteer"
  | "object"
  | "set-cookie";

export const getCookies = async (
  uri: string,
  format:
    | Format
    | (<T extends unknown>(err: Error | null, result?: T) => void)
    | null,
  callback: <T extends unknown>(err: Error | null, result?: T) => void,
  profile: string = "Default"
) => {
  let path: string;
  if (process.platform === "darwin") {
    path =
      process.env.HOME +
      `/Library/Application Support/Google/Chrome/${profile}/Cookies`;
    ITERATIONS = 1003;
  } else if (process.platform === "linux") {
    path = process.env.HOME + `/.config/google-chrome/${profile}/Cookies`;
    ITERATIONS = 1;
  } else {
    return callback(new Error("Only Mac or Linux are supported."));
  }

  let db = new sqlite3.Database(path);
  let dbClosed = false;

  if (format instanceof Function) {
    callback = format;
    format = null;
  }

  const parsedUrl = url.parse(uri);

  if (!(parsedUrl.protocol && parsedUrl.hostname)) {
    return callback(
      new Error(
        "Could not parse URI, format should be http://www.example.com/path/"
      )
    );
  }

  if (dbClosed) {
    db = new sqlite3.Database(path);
    dbClosed = false;
  }

  db.on("error", callback);

  getDerivedKey((err, derivedKey) => {
    if (err) {
      return callback(err);
    }

    db.serialize(() => {
      const cookies: Cookie[] = [];

      const domain = tld.getDomain(uri);

      if (!domain) {
        return callback(
          new Error(
            "Could not parse domain from URI, format should be http://www.example.com/path/"
          )
        );
      }

      // ORDER BY tries to match sort order specified in
      // RFC 6265 - Section 5.4, step 2
      // http://tools.ietf.org/html/rfc6265#section-5.4

      db.each(
        `SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, creation_utc, is_httponly, has_expires, is_persistent FROM cookies where host_key like '%${domain}' ORDER BY LENGTH(path) DESC, creation_utc ASC`,
        (err: Error, cookie: Cookie) => {
          let encryptedValue: string;

          if (err) {
            return callback(err);
          }

          if (cookie.value === "" && cookie.encrypted_value.length > 0) {
            encryptedValue = cookie.encrypted_value;
            cookie.value = decrypt(derivedKey, encryptedValue);
          }

          cookies.push(cookie);
        },
        () => {
          const host = parsedUrl.hostname ?? "";
          const path = parsedUrl.path ?? "";
          const isSecure = parsedUrl.protocol
            ? !!parsedUrl.protocol.match("https")
            : false;

          let validCookies: Cookie[] = [];
          let output: unknown;

          cookies.forEach((cookie) => {
            if (
              (cookie.is_secure && !isSecure) ||
              !cookie.host_key ||
              !cookie.path
            ) {
              return;
            }

            if (!tough.domainMatch(host, cookie.host_key, true)) {
              return;
            }

            if (!tough.pathMatch(path, cookie.path)) {
              return;
            }

            validCookies.push(cookie);
          });

          const filteredCookies: Cookie[] = [];
          const keys: { [k: string]: boolean } = {};

          validCookies.reverse().forEach(function (cookie) {
            if (typeof keys[cookie.name] === "undefined") {
              filteredCookies.push(cookie);
              keys[cookie.name] = true;
            }
          });

          validCookies = filteredCookies.reverse();

          switch (format) {
            case "curl": {
              output = convertRawToNetscapeCookieFileFormat(
                validCookies,
                domain
              );
              break;
            }
            case "jar": {
              output = convertRawToJar(validCookies, uri);
              break;
            }
            case "set-cookie": {
              output = convertRawToSetCookieStrings(validCookies);
              break;
            }
            case "header": {
              output = convertRawToHeader(validCookies);
              break;
            }

            case "puppeteer": {
              output = convertRawToPuppeteerState(validCookies);
              break;
            }

            case "object":
            /* falls through */
            default:
              output = convertRawToObject(validCookies);
              break;
          }

          db.close((err) => {
            if (!err) {
              dbClosed = true;
            }
            return callback(null, output);
          });
        }
      );
    });
  });
};

export const getCookiesPromised = async (
  uri: string,
  format: Format,
  profile: string = "Default"
) => {
  return new Promise((resolve, reject) => {
    getCookies(
      uri,
      format,
      (err, cookies) => {
        if (err) {
          return reject(err);
        }
        resolve(cookies);
      },
      profile
    );
  });
};
