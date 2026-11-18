const ResearchDAO = require("../data/research-dao").ResearchDAO;
const http = require("http");
const https = require("https");
const dns = require("dns");
const net = require("net");
const {
    environmentalScripts
} = require("../../config/config");

function parseIPv6(ip) {
    let address = ip.toLowerCase();
    const zoneIndex = address.indexOf("%");
    if (zoneIndex !== -1) {
        address = address.slice(0, zoneIndex);
    }

    let ipv4 = null;
    if (address.includes(".")) {
        const lastColon = address.lastIndexOf(":");
        if (lastColon === -1) {
            return null;
        }
        const ipv4Part = address.slice(lastColon + 1);
        if (!net.isIPv4(ipv4Part)) {
            return null;
        }
        ipv4 = ipv4Part.split(".").map(Number);
        address = address.slice(0, lastColon + 1) + "0:0";
    }

    let groups;
    if (address.includes("::")) {
        const parts = address.split("::");
        if (parts.length !== 2) {
            return null;
        }
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        const missing = 8 - left.length - right.length;
        if (missing < 0) {
            return null;
        }
        groups = [...left, ...Array(missing).fill("0"), ...right];
    } else {
        groups = address.split(":");
        if (groups.length !== 8) {
            return null;
        }
    }

    if (groups.length !== 8) {
        return null;
    }

    const parsed = groups.map(group => parseInt(group, 16));
    if (parsed.some(Number.isNaN)) {
        return null;
    }

    if (ipv4) {
        parsed[6] = (ipv4[0] << 8) | ipv4[1];
        parsed[7] = (ipv4[2] << 8) | ipv4[3];
    }

    return parsed;
}

function isPrivateIP(ip) {
    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        const a = parts[0];
        const b = parts[1];
        const c = parts[2];
        return a === 0 ||
            a === 10 ||
            (a === 100 && b >= 64 && b <= 127) ||
            a === 127 ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 0 && (c === 0 || c === 2)) ||
            (a === 192 && b === 88 && c === 99) ||
            (a === 192 && b === 168) ||
            (a === 198 && (b === 18 || b === 19)) ||
            (a === 198 && b === 51 && c === 100) ||
            (a === 203 && b === 0 && c === 113) ||
            a >= 224;
    }

    if (net.isIPv6(ip)) {
        const groups = parseIPv6(ip);
        if (!groups) {
            return true;
        }
        if ((groups[0] & 0xe000) !== 0x2000) {
            return true;
        }
        if (groups[0] === 0x2001 && groups[1] === 0x0db8) {
            return true;
        }
        if (groups[0] === 0x2001 && groups[1] === 0x0000) {
            return true;
        }
        if (groups[0] === 0x2002) {
            return true;
        }
        return false;
    }

    return true;
}

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = async (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.url !== "string" || typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid URL");
            }

            let url;
            try {
                url = new URL(req.query.url + req.query.symbol);
            } catch (e) {
                return res.status(400).send("Invalid URL");
            }

            if (!["http:", "https:"].includes(url.protocol)) {
                return res.status(400).send("Invalid URL");
            }

            let hostname = url.hostname;
            if (hostname.startsWith("[") && hostname.endsWith("]")) {
                hostname = hostname.slice(1, -1);
            }
            if (!hostname) {
                return res.status(400).send("Invalid URL");
            }

            let addresses;
            try {
                addresses = await dns.promises.lookup(hostname, { all: true });
            } catch (e) {
                return res.status(400).send("Invalid URL");
            }

            if (!addresses.length || addresses.some(addr => isPrivateIP(addr.address))) {
                return res.status(400).send("Invalid URL");
            }

            const addressEntry = addresses.find(addr => addr.family === 4) || addresses[0];
            const address = addressEntry.address;
            const port = url.port ? Number(url.port) : (url.protocol === "https:" ? 443 : 80);
            const client = url.protocol === "https:" ? https : http;
            const options = {
                protocol: url.protocol,
                hostname: address,
                port,
                path: url.pathname + url.search,
                method: "GET",
                headers: {
                    Host: url.host
                }
            };

            if (url.protocol === "https:" && net.isIP(hostname) === 0) {
                options.servername = hostname;
            }

            const request = client.request(options, (response) => {
                if (response.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                response.on("data", (chunk) => {
                    res.write(chunk);
                });
                response.on("end", () => {
                    if (!res.writableEnded) {
                        res.end();
                    }
                });
                response.on("error", () => {
                    if (!res.writableEnded) {
                        res.end();
                    }
                });
            });

            request.on("error", () => {
                if (!res.writableEnded) {
                    if (!res.headersSent) {
                        res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                        res.write("\n\n");
                    }
                    res.end();
                }
            });

            request.end();
            return;
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;