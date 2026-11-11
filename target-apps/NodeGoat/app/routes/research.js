const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const STOCK_QUOTES = [
    { symbol: "AAPL", url: "http://download.finance.yahoo.com/d/quotes.csv?s=AAPL" },
    { symbol: "GOOG", url: "http://download.finance.yahoo.com/d/quotes.csv?s=GOOG" },
    { symbol: "GOOGL", url: "http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL" },
    { symbol: "MSFT", url: "http://download.finance.yahoo.com/d/quotes.csv?s=MSFT" },
    { symbol: "AMZN", url: "http://download.finance.yahoo.com/d/quotes.csv?s=AMZN" },
    { symbol: "TSLA", url: "http://download.finance.yahoo.com/d/quotes.csv?s=TSLA" },
    { symbol: "FB", url: "http://download.finance.yahoo.com/d/quotes.csv?s=FB" },
    { symbol: "META", url: "http://download.finance.yahoo.com/d/quotes.csv?s=META" },
    { symbol: "NFLX", url: "http://download.finance.yahoo.com/d/quotes.csv?s=NFLX" },
    { symbol: "NVDA", url: "http://download.finance.yahoo.com/d/quotes.csv?s=NVDA" },
    { symbol: "IBM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=IBM" },
    { symbol: "ORCL", url: "http://download.finance.yahoo.com/d/quotes.csv?s=ORCL" },
    { symbol: "INTC", url: "http://download.finance.yahoo.com/d/quotes.csv?s=INTC" },
    { symbol: "AMD", url: "http://download.finance.yahoo.com/d/quotes.csv?s=AMD" },
    { symbol: "JPM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=JPM" },
    { symbol: "BAC", url: "http://download.finance.yahoo.com/d/quotes.csv?s=BAC" },
    { symbol: "WMT", url: "http://download.finance.yahoo.com/d/quotes.csv?s=WMT" },
    { symbol: "DIS", url: "http://download.finance.yahoo.com/d/quotes.csv?s=DIS" },
    { symbol: "KO", url: "http://download.finance.yahoo.com/d/quotes.csv?s=KO" },
    { symbol: "PEP", url: "http://download.finance.yahoo.com/d/quotes.csv?s=PEP" },
    { symbol: "NKE", url: "http://download.finance.yahoo.com/d/quotes.csv?s=NKE" },
    { symbol: "XOM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=XOM" },
    { symbol: "CVX", url: "http://download.finance.yahoo.com/d/quotes.csv?s=CVX" },
    { symbol: "PFE", url: "http://download.finance.yahoo.com/d/quotes.csv?s=PFE" },
    { symbol: "MRK", url: "http://download.finance.yahoo.com/d/quotes.csv?s=MRK" },
    { symbol: "ABBV", url: "http://download.finance.yahoo.com/d/quotes.csv?s=ABBV" },
    { symbol: "T", url: "http://download.finance.yahoo.com/d/quotes.csv?s=T" },
    { symbol: "VZ", url: "http://download.finance.yahoo.com/d/quotes.csv?s=VZ" },
    { symbol: "V", url: "http://download.finance.yahoo.com/d/quotes.csv?s=V" },
    { symbol: "MA", url: "http://download.finance.yahoo.com/d/quotes.csv?s=MA" },
    { symbol: "PYPL", url: "http://download.finance.yahoo.com/d/quotes.csv?s=PYPL" },
    { symbol: "ADBE", url: "http://download.finance.yahoo.com/d/quotes.csv?s=ADBE" },
    { symbol: "CRM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=CRM" },
    { symbol: "CSCO", url: "http://download.finance.yahoo.com/d/quotes.csv?s=CSCO" },
    { symbol: "QCOM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=QCOM" },
    { symbol: "TXN", url: "http://download.finance.yahoo.com/d/quotes.csv?s=TXN" },
    { symbol: "AVGO", url: "http://download.finance.yahoo.com/d/quotes.csv?s=AVGO" },
    { symbol: "COST", url: "http://download.finance.yahoo.com/d/quotes.csv?s=COST" },
    { symbol: "HD", url: "http://download.finance.yahoo.com/d/quotes.csv?s=HD" },
    { symbol: "MCD", url: "http://download.finance.yahoo.com/d/quotes.csv?s=MCD" },
    { symbol: "BA", url: "http://download.finance.yahoo.com/d/quotes.csv?s=BA" },
    { symbol: "CAT", url: "http://download.finance.yahoo.com/d/quotes.csv?s=CAT" },
    { symbol: "GE", url: "http://download.finance.yahoo.com/d/quotes.csv?s=GE" },
    { symbol: "F", url: "http://download.finance.yahoo.com/d/quotes.csv?s=F" },
    { symbol: "GM", url: "http://download.finance.yahoo.com/d/quotes.csv?s=GM" }
];

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.toUpperCase();
            const quote = STOCK_QUOTES.find(q => q.symbol === symbol);

            if (!quote) {
                return res.status(400).send("Invalid stock symbol");
            }

            return needle.get(quote.url, (error, newResponse, body) => {
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