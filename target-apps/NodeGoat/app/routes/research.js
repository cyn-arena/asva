const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const { URL } = require("url");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);
    const allowedHost = "dev.markitondemand.com";

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            let parsedUrl;
            try {
                parsedUrl = new URL(req.query.url + encodeURIComponent(req.query.symbol));
            } catch (error) {
                res.writeHead(400, {
                    "Content-Type": "text/plain"
                });
                return res.end("Invalid URL");
            }

            if ((parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") ||
                parsedUrl.hostname !== allowedHost ||
                parsedUrl.username ||
                parsedUrl.password ||
                (parsedUrl.port && parsedUrl.port !== "80" && parsedUrl.port !== "443")) {
                res.writeHead(400, {
                    "Content-Type": "text/plain"
                });
                return res.end("Invalid URL");
            }

            return needle.get(parsedUrl.toString(), { follow_max: 0 }, (error, newResponse, body) => {
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