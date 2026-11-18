const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function createResponseHandler(res) {
    return (error, newResponse, body) => {
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
}

const STOCK_FETCHERS = new Map([
    ["AAPL", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AAPL", createResponseHandler(res))],
    ["GOOG", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOG", createResponseHandler(res))],
    ["GOOGL", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL", createResponseHandler(res))],
    ["MSFT", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MSFT", createResponseHandler(res))],
    ["AMZN", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMZN", createResponseHandler(res))],
    ["TSLA", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TSLA", createResponseHandler(res))],
    ["FB", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=FB", createResponseHandler(res))],
    ["META", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=META", createResponseHandler(res))],
    ["NFLX", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NFLX", createResponseHandler(res))],
    ["NVDA", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NVDA", createResponseHandler(res))],
    ["IBM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=IBM", createResponseHandler(res))],
    ["ORCL", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ORCL", createResponseHandler(res))],
    ["INTC", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=INTC", createResponseHandler(res))],
    ["AMD", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMD", createResponseHandler(res))],
    ["JPM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=JPM", createResponseHandler(res))],
    ["BAC", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BAC", createResponseHandler(res))],
    ["WMT", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=WMT", createResponseHandler(res))],
    ["DIS", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=DIS", createResponseHandler(res))],
    ["KO", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=KO", createResponseHandler(res))],
    ["PEP", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PEP", createResponseHandler(res))],
    ["NKE", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NKE", createResponseHandler(res))],
    ["XOM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=XOM", createResponseHandler(res))],
    ["CVX", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CVX", createResponseHandler(res))],
    ["PFE", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PFE", createResponseHandler(res))],
    ["MRK", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MRK", createResponseHandler(res))],
    ["ABBV", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ABBV", createResponseHandler(res))],
    ["T", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=T", createResponseHandler(res))],
    ["VZ", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=VZ", createResponseHandler(res))],
    ["V", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=V", createResponseHandler(res))],
    ["MA", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MA", createResponseHandler(res))],
    ["PYPL", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PYPL", createResponseHandler(res))],
    ["ADBE", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ADBE", createResponseHandler(res))],
    ["CRM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CRM", createResponseHandler(res))],
    ["CSCO", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CSCO", createResponseHandler(res))],
    ["QCOM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=QCOM", createResponseHandler(res))],
    ["TXN", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TXN", createResponseHandler(res))],
    ["AVGO", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AVGO", createResponseHandler(res))],
    ["COST", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=COST", createResponseHandler(res))],
    ["HD", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=HD", createResponseHandler(res))],
    ["MCD", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MCD", createResponseHandler(res))],
    ["BA", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BA", createResponseHandler(res))],
    ["CAT", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CAT", createResponseHandler(res))],
    ["GE", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GE", createResponseHandler(res))],
    ["F", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=F", createResponseHandler(res))],
    ["GM", (res) => needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GM", createResponseHandler(res))]
]);

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.trim().toUpperCase();
            const fetcher = STOCK_FETCHERS.get(symbol);

            if (!fetcher) {
                return res.status(400).send("Invalid stock symbol");
            }

            return fetcher(res);
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;