const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const dns = require("dns");
const net = require("net");
const {
    environmentalScripts
} = require("../../config/config");

function isPrivateIP(ip) {
    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        return parts[0] === 10 ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168) ||
            parts[0] === 127 ||
            (parts[0] === 169 && parts[1] === 254) ||
            parts[0] === 0 ||
            (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
            (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) ||
            (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) ||
            (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) ||
            (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) ||
            parts[0] >= 224;
    }
    if (net.isIPv6(ip)) {
        const normalized = ip.toLowerCase();
        if (normalized === "::1" || normalized === "::") return true;
        if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
        if (normalized.startsWith("fe80")) return true;
        if (normalized.startsWith("ff")) return true;
        if (normalized.startsWith("::ffff:")) return true;
        return false;
    }
    return true;
}

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = async (req, res) => {

        if (req.query.symbol) {
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
            try {
                const addresses = await dns.promises.lookup(hostname, { all: true });
                if (addresses.some(addr => isPrivateIP(addr.address))) {
                    return res.status(400).send("Invalid URL");
                }
            } catch (e) {
                return res.status(400).send("Invalid URL");
            }
            return needle.get(url.toString(), { follow_max: 0 }, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;