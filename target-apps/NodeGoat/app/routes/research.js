const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            let url;
            try {
                url = new URL(String(req.query.url) + String(req.query.symbol));
            } catch (error) {
                url = null;
            }

            if (!url ||
                (url.protocol !== "http:" && url.protocol !== "https:") ||
                url.hostname !== "finance.yahoo.com" ||
                url.username ||
                url.password) {
                res.writeHead(400, {
                    "Content-Type": "text/plain"
                });
                return res.end("Invalid research URL");
            }

            return needle.get(url.toString(), (error, newResponse, body) => {
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