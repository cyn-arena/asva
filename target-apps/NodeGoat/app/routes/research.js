const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);
    const researchUrl = "https://www.google.com/finance?q=";

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (!/^[A-Za-z0-9.\-^=:]{1,20}$/.test(req.query.symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }
            const url = researchUrl + encodeURIComponent(req.query.symbol);
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

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;