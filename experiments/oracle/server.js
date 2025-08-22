#!/usr/bin/env node
// Tiny local webserver to serve our test page
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = 8081;

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3W5L7J7F1R87ZPp6vhGN6Y80s31vaO1YCk44gX/L0IUCDv49
9ACmxe0jliASGhMUpj8V+58I8cDzowbXBEzWzbwg4wSG9bB5/UizAczR1kXtT4Ic
A/GhtCymdSpBi5qRgMsKf4OJi2nDw9E+6PXj2rEL7ukSfzM2MnEh/0pS7TL/qCyJ
tU0QZqOz5FZP2TA89bDzMUbhTU96INfow7PSZePAyXvt+gusTBSyxc4fPKhnBm+F
ScKjENb9TBN4drak5OFsWk9JKbyqMIfWeMo9Ne3M+e9DCxausQmj1SCkFEqNPUVw
w4RLWaqU4IwN3K4qly10qxu6LHv/eFJZYuRE2QIDAQABAoIBAA4seDmuNBWfSSr+
iYrPDtlrbEEs/0ulHaSTOzS23HH9gZM6HPcYb5RtyIBcjywSGplFon+Xv3fSFQZT
csH4tSs4JpbBfG4PnM9kruinlqrzkOws9OQfvG0PCpynVsi73SJ0XLiqz8wXugs3
wqIg0zP1b0EctC1mNsrlyPpRZJuAMK+zi3aMaxyUwtCp6Ps8x5FfsWRIv+ukO40Y
c1NmC63ZCl5jPDxMK/miEScby88H5CUwqfuJp0geg/n24x/X6KhSYZaB+A1Pt7lU
MvOlbADxolpB+SjwroF3AmNMhgV0T5qOAXHRDibaObxnwZV/NaU8pk7SzjpfICZv
yD9nLx0CgYEA+XZPAED4dN4KBl/QFpXHoRKi2OSWOhrc+5V0uN+rv6EYCab7KWBt
xosu5POVw72vlwlCKFdmF7mGnvoVutC7HHbdgMqb1/mSSupMPj1xNnjNQysg6pZQ
4fJBMn50QBlsnL2Fkb3km7MjBuqA4kLAE4qsSXblFiQiG9Ttj14N528CgYEA4zvr
n6lt9CRYDT1yaYZtvzYIgLNylALmPz3TFM4KNFbI5R8cGYOvFwM6s++TiKpByaMt
SqB89akZj+eCxRwf/s3iHihpoPQhhXkh4tBZG9TEETqeDJt44Yu8EEo6za05C9iv
0lbwi9WeKK6dQ9ASZChAwQ10o5g6AJdA/JjrNDcCgYEAzGXVwT161jcAO8zRsU+0
LBQa/l/9f0p3emQxKTGLhg42peH9tR9fkuiD2fCD68hGURiy7l7+Nb47wZLjrxhL
17zFLTvViZbh+SQUqIKrephshvaVl+DmENvv87GNCuBKD/txr8LJx5F1x7rpM3rB
6sEa/W6/se6VS/yhUXEdL10CgYBJwze3em5g5DNZCOtM6gBSI54a+SVmepJ3UQBm
LoQNfWZ1SeX7Ok3p8Hhr1IdVw77bT4byRKqLrDrKBeLjTT/tnLOcCo5PWzBOfYXM
dMmYSTbkSNzpRsa0oIGJ4C66eVKdT9ezNdmb6toOZrBSRQbTUGXExTNpr46UhoTn
+lPPfQKBgQDQ6/lil3bARwOUT4ycMd8tZodZGKY1zpQvWX4aQnbM5xxFK6JmF5b7
qnPeXXEW6bGkUobl1CD6W2gR/s8CuG1gvU+PTgVbQkZgZNKQPG7R186YTLYU3ode
rG9WUtMAVHSsec7DM6uYBl17SEHTDKM2Jk+KxIbl4tBLLv2mP8SnIA==
-----END RSA PRIVATE KEY-----
`;

http
  .createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Add CORS headers for cross-origin requests
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(200);
      res.end();
      return;
    }

    // RSA decryption endpoint
    if (url.pathname === "/decrypt-rsa") {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString();
        });
        req.on("end", () => {
          try {
            const { encryptedData } = JSON.parse(body);

            const encryptedBuffer = Buffer.from(encryptedData, "base64");
            console.log(encryptedBuffer.length);
            const keyObj = crypto.createPrivateKey(privateKey);

            const decrypted = crypto.privateDecrypt(
              {
                key: keyObj,
                padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5
              },
              encryptedBuffer
            );

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                success: true,
                // Send lengths explicitly to avoid confusion
                ciphertextBytes: encryptedBuffer.length, // expect 256
                plaintextBytes: decrypted.length, // <= 245
                plaintextB64: decrypted.toString("base64"),
                // (hex / utf8 previews are optional)
                plaintextHexHead: decrypted.subarray(0, 16).toString("hex"),
                utf8Preview: decrypted.toString(
                  "utf8",
                  0,
                  Math.min(decrypted.length, 100)
                ),
              })
            );
          } catch (error) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: error.message }));
          }
        });
      } else {
        res.writeHead(405);
        res.end("Method not allowed");
      }
      return;
    }

    // Serve static files
    let filePath = path.join(
      __dirname,
      url.pathname === "/" ? "index.html" : url.pathname
    );
    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(404);
        res.end("Not found");
      } else {
        res.writeHead(200, {
          "Content-Type": filePath.endsWith(".js")
            ? "application/javascript"
            : "text/html",
        });
        res.end(content);
      }
    });
  })
  .listen(PORT, () => {
    console.log(`[*] Server running at http://127.0.0.1:${PORT}`);
  });
