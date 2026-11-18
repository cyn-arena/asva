const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const YAHOO_RESEARCH_URL = "http://finance.yahoo.com/d/quotes.csv?s=";
const YAHOO_RESEARCH_URL_SECURE = "https://finance.yahoo.com/d/quotes.csv?s=";
const MARKIT_RESEARCH_URL = "http://dev.markitondemand.com/MODApis/Api/v2/Quote/json?symbol=";
const MARKIT_RESEARCH_URL_SECURE = "https://dev.markitondemand.com/MODApis/Api/v2/Quote/json?symbol=";

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            const requestedUrl = req.query.url;
            let baseUrl;

            if (requestedUrl === YAHOO_RESEARCH_URL) {
                baseUrl = YAHOO_RESEARCH_URL;
            } else if (requestedUrl === YAHOO_RESEARCH_URL_SECURE) {
                baseUrl = YAHOO_RESEARCH_URL_SECURE;
            } else if (requestedUrl === MARKIT_RESEARCH_URL) {
                baseUrl = MARKIT_RESEARCH_URL;
            } else if (requestedUrl === MARKIT_RESEARCH_URL_SECURE) {
                baseUrl = MARKIT_RESEARCH_URL_SECURE;
            } else {
                return res.status(400).send("Invalid research URL");
            }

            const url = baseUrl + encodeURIComponent(req.query.symbol);
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