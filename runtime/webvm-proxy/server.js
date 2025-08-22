const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const port = 8000;

const mimeTypes = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".ext2": "application/octet-stream",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
};

const server = http.createServer((req, res) => {
  // Parse URL to get pathname and query parameters
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const queryParams = parsedUrl.query;

  // Log request for debugging
  console.log(
    `${new Date().toISOString()} ${req.method} ${pathname}`,
    Object.keys(queryParams).length > 0 ? queryParams : ""
  );

  // Handle webvm-proxy.js with query parameters
  if (pathname === "/webvm-proxy.js") {
    // Read the base webvm-proxy.js file and serve it
    filePath = path.join(__dirname, "webvm-proxy.js");
  } else {
    filePath = path.join(__dirname, pathname === "/" ? "index.html" : pathname);
  }

  const ext = path.extname(filePath);
  const mimeType = mimeTypes[ext] || "application/octet-stream";

  fs.stat(filePath, (err, stats) => {
    if (err) {
      if (err.code === "ENOENT") {
        res.writeHead(404);
        res.end("Not Found");
      } else {
        res.writeHead(500);
        res.end("Internal Server Error");
      }
      return;
    }

    // Set cross-origin isolation headers required for CheerpX
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", mimeType);
    res.setHeader("Last-Modified", stats.mtime.toUTCString());
    res.setHeader("Accept-Ranges", "bytes");

    // Handle Range requests for HttpBytesDevice
    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;
      const chunksize = end - start + 1;

      const stream = fs.createReadStream(filePath, { start, end });
      res.setHeader("Content-Range", `bytes ${start}-${end}/${stats.size}`);
      res.setHeader("Content-Length", chunksize);
      res.writeHead(206, "Partial Content");
      stream.pipe(res);
    } else {
      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.writeHead(500);
          res.end("Internal Server Error");
          return;
        }

        res.setHeader("Content-Length", data.length);
        res.writeHead(200);
        res.end(data);
      });
    }
  });
});

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log("Cross-origin isolation enabled for CheerpX");
});
