const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    const handleStockResponse = (res) => (error, newResponse, body) => {
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

    const getStock = (symbol, res) => {
        switch (symbol) {
            case "AAPL":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AAPL", handleStockResponse(res));
            case "GOOG":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOG", handleStockResponse(res));
            case "GOOGL":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL", handleStockResponse(res));
            case "MSFT":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MSFT", handleStockResponse(res));
            case "AMZN":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMZN", handleStockResponse(res));
            case "TSLA":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TSLA", handleStockResponse(res));
            case "FB":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=FB", handleStockResponse(res));
            case "META":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=META", handleStockResponse(res));
            case "NFLX":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NFLX", handleStockResponse(res));
            case "NVDA":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NVDA", handleStockResponse(res));
            case "IBM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=IBM", handleStockResponse(res));
            case "ORCL":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ORCL", handleStockResponse(res));
            case "INTC":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=INTC", handleStockResponse(res));
            case "AMD":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMD", handleStockResponse(res));
            case "JPM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=JPM", handleStockResponse(res));
            case "BAC":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BAC", handleStockResponse(res));
            case "WMT":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=WMT", handleStockResponse(res));
            case "DIS":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=DIS", handleStockResponse(res));
            case "KO":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=KO", handleStockResponse(res));
            case "PEP":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PEP", handleStockResponse(res));
            case "NKE":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NKE", handleStockResponse(res));
            case "XOM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=XOM", handleStockResponse(res));
            case "CVX":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CVX", handleStockResponse(res));
            case "PFE":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PFE", handleStockResponse(res));
            case "MRK":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MRK", handleStockResponse(res));
            case "ABBV":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ABBV", handleStockResponse(res));
            case "T":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=T", handleStockResponse(res));
            case "VZ":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=VZ", handleStockResponse(res));
            case "V":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=V", handleStockResponse(res));
            case "MA":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MA", handleStockResponse(res));
            case "PYPL":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PYPL", handleStockResponse(res));
            case "ADBE":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ADBE", handleStockResponse(res));
            case "CRM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CRM", handleStockResponse(res));
            case "CSCO":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CSCO", handleStockResponse(res));
            case "QCOM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=QCOM", handleStockResponse(res));
            case "TXN":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TXN", handleStockResponse(res));
            case "AVGO":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AVGO", handleStockResponse(res));
            case "COST":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=COST", handleStockResponse(res));
            case "HD":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=HD", handleStockResponse(res));
            case "MCD":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MCD", handleStockResponse(res));
            case "BA":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BA", handleStockResponse(res));
            case "CAT":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CAT", handleStockResponse(res));
            case "GE":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GE", handleStockResponse(res));
            case "F":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=F", handleStockResponse(res));
            case "GM":
                return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GM", handleStockResponse(res));
            default:
                return res.status(400).send("Invalid stock symbol");
        }
    };

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            if (typeof req.query.symbol !== "string") {
                return res.status(400).send("Invalid stock symbol");
            }

            const symbol = req.query.symbol.toUpperCase();
            if (!/^[A-Z]{1,5}$/.test(symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }

            return getStock(symbol, res);
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;