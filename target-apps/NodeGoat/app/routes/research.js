const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const STOCK_URLS = Object.freeze({
    AAPL: "http://download.finance.yahoo.com/d/quotes.csv?s=AAPL",
    GOOG: "http://download.finance.yahoo.com/d/quotes.csv?s=GOOG",
    GOOGL: "http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL",
    MSFT: "http://download.finance.yahoo.com/d/quotes.csv?s=MSFT",
    AMZN: "http://download.finance.yahoo.com/d/quotes.csv?s=AMZN",
    TSLA: "http://download.finance.yahoo.com/d/quotes.csv?s=TSLA",
    FB: "http://download.finance.yahoo.com/d/quotes.csv?s=FB",
    META: "http://download.finance.yahoo.com/d/quotes.csv?s=META",
    NFLX: "http://download.finance.yahoo.com/d/quotes.csv?s=NFLX",
    NVDA: "http://download.finance.yahoo.com/d/quotes.csv?s=NVDA",
    IBM: "http://download.finance.yahoo.com/d/quotes.csv?s=IBM",
    ORCL: "http://download.finance.yahoo.com/d/quotes.csv?s=ORCL",
    INTC: "http://download.finance.yahoo.com/d/quotes.csv?s=INTC",
    AMD: "http://download.finance.yahoo.com/d/quotes.csv?s=AMD",
    JPM: "http://download.finance.yahoo.com/d/quotes.csv?s=JPM",
    BAC: "http://download.finance.yahoo.com/d/quotes.csv?s=BAC",
    WMT: "http://download.finance.yahoo.com/d/quotes.csv?s=WMT",
    DIS: "http://download.finance.yahoo.com/d/quotes.csv?s=DIS",
    KO: "http://download.finance.yahoo.com/d/quotes.csv?s=KO",
    PEP: "http://download.finance.yahoo.com/d/quotes.csv?s=PEP",
    NKE: "http://download.finance.yahoo.com/d/quotes.csv?s=NKE",
    XOM: "http://download.finance.yahoo.com/d/quotes.csv?s=XOM",
    CVX: "http://download.finance.yahoo.com/d/quotes.csv?s=CVX",
    PFE: "http://download.finance.yahoo.com/d/quotes.csv?s=PFE",
    MRK: "http://download.finance.yahoo.com/d/quotes.csv?s=MRK",
    ABBV: "http://download.finance.yahoo.com/d/quotes.csv?s=ABBV",
    T: "http://download.finance.yahoo.com/d/quotes.csv?s=T",
    VZ: "http://download.finance.yahoo.com/d/quotes.csv?s=VZ",
    V: "http://download.finance.yahoo.com/d/quotes.csv?s=V",
    MA: "http://download.finance.yahoo.com/d/quotes.csv?s=MA",
    PYPL: "http://download.finance.yahoo.com/d/quotes.csv?s=PYPL",
    ADBE: "http://download.finance.yahoo.com/d/quotes.csv?s=ADBE",
    CRM: "http://download.finance.yahoo.com/d/quotes.csv?s=CRM",
    CSCO: "http://download.finance.yahoo.com/d/quotes.csv?s=CSCO",
    QCOM: "http://download.finance.yahoo.com/d/quotes.csv?s=QCOM",
    TXN: "http://download.finance.yahoo.com/d/quotes.csv?s=TXN",
    AVGO: "http://download.finance.yahoo.com/d/quotes.csv?s=AVGO",
    COST: "http://download.finance.yahoo.com/d/quotes.csv?s=COST",
    HD: "http://download.finance.yahoo.com/d/quotes.csv?s=HD",
    MCD: "http://download.finance.yahoo.com/d/quotes.csv?s=MCD",
    BA: "http://download.finance.yahoo.com/d/quotes.csv?s=BA",
    CAT: "http://download.finance.yahoo.com/d/quotes.csv?s=CAT",
    GE: "http://download.finance.yahoo.com/d/quotes.csv?s=GE",
    F: "http://download.finance.yahoo.com/d/quotes.csv?s=F",
    GM: "http://download.finance.yahoo.com/d/quotes.csv?s=GM"
});

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.toUpperCase();
            if (!Object.prototype.hasOwnProperty.call(STOCK_URLS, symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }

            const url = STOCK_URLS[symbol];
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