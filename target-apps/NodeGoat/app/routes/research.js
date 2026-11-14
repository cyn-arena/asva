const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function fetchStock(symbol, res) {
    const url = "http://download.finance.yahoo.com/d/quotes.csv?s=" + encodeURIComponent(symbol);
    return needle.get(url, (error, newResponse, body) => {
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

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.trim();
            if (!/^[A-Za-z0-9.\-]{1,10}$/.test(symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }

            return fetchStock(symbol, res);
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;