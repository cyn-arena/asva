const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const STOCK_QUOTE_REQUESTS = {
    AAPL: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AAPL", callback),
    GOOG: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOG", callback),
    GOOGL: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL", callback),
    MSFT: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MSFT", callback),
    AMZN: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMZN", callback),
    TSLA: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TSLA", callback),
    FB: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=FB", callback),
    META: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=META", callback),
    NFLX: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NFLX", callback),
    NVDA: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NVDA", callback),
    IBM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=IBM", callback),
    ORCL: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ORCL", callback),
    INTC: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=INTC", callback),
    AMD: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMD", callback),
    JPM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=JPM", callback),
    BAC: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BAC", callback),
    WMT: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=WMT", callback),
    DIS: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=DIS", callback),
    KO: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=KO", callback),
    PEP: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PEP", callback),
    NKE: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NKE", callback),
    XOM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=XOM", callback),
    CVX: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CVX", callback),
    PFE: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PFE", callback),
    MRK: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MRK", callback),
    ABBV: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ABBV", callback),
    T: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=T", callback),
    VZ: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=VZ", callback),
    V: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=V", callback),
    MA: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MA", callback),
    PYPL: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PYPL", callback),
    ADBE: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ADBE", callback),
    CRM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CRM", callback),
    CSCO: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CSCO", callback),
    QCOM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=QCOM", callback),
    TXN: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TXN", callback),
    AVGO: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AVGO", callback),
    COST: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=COST", callback),
    HD: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=HD", callback),
    MCD: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MCD", callback),
    BA: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BA", callback),
    CAT: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CAT", callback),
    GE: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GE", callback),
    F: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=F", callback),
    GM: (callback) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GM", callback)
};

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.toUpperCase();
            if (!Object.prototype.hasOwnProperty.call(STOCK_QUOTE_REQUESTS, symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }

            const handleResponse = (error, newResponse, body) => {
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
            };

            return STOCK_QUOTE_REQUESTS[symbol](handleResponse);
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;