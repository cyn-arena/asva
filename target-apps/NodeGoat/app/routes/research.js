const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const { URL } = require("url");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const urlString = "http://download.finance.yahoo.com/d/quotes.csv?s=" + encodeURIComponent(req.query.symbol);
            const url = new URL(urlString);

            if (url.protocol !== "http:" || url.hostname !== "download.finance.yahoo.com") {
                return res.status(400).send("Invalid URL");
            }

            return needle.get(url.href, (error, newResponse, body) => {
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