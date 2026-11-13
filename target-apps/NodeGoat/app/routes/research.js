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
            if (typeof req.query.symbol !== "string") {
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

            switch (req.query.symbol.toUpperCase()) {
                case "AAPL":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AAPL", handleResponse);
                case "GOOG":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOG", handleResponse);
                case "GOOGL":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GOOGL", handleResponse);
                case "MSFT":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MSFT", handleResponse);
                case "AMZN":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMZN", handleResponse);
                case "TSLA":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TSLA", handleResponse);
                case "FB":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=FB", handleResponse);
                case "META":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=META", handleResponse);
                case "NFLX":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NFLX", handleResponse);
                case "NVDA":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NVDA", handleResponse);
                case "IBM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=IBM", handleResponse);
                case "ORCL":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ORCL", handleResponse);
                case "INTC":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=INTC", handleResponse);
                case "AMD":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AMD", handleResponse);
                case "JPM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=JPM", handleResponse);
                case "BAC":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BAC", handleResponse);
                case "WMT":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=WMT", handleResponse);
                case "DIS":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=DIS", handleResponse);
                case "KO":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=KO", handleResponse);
                case "PEP":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PEP", handleResponse);
                case "NKE":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=NKE", handleResponse);
                case "XOM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=XOM", handleResponse);
                case "CVX":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CVX", handleResponse);
                case "PFE":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PFE", handleResponse);
                case "MRK":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MRK", handleResponse);
                case "ABBV":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ABBV", handleResponse);
                case "T":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=T", handleResponse);
                case "VZ":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=VZ", handleResponse);
                case "V":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=V", handleResponse);
                case "MA":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MA", handleResponse);
                case "PYPL":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=PYPL", handleResponse);
                case "ADBE":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=ADBE", handleResponse);
                case "CRM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CRM", handleResponse);
                case "CSCO":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CSCO", handleResponse);
                case "QCOM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=QCOM", handleResponse);
                case "TXN":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=TXN", handleResponse);
                case "AVGO":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=AVGO", handleResponse);
                case "COST":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=COST", handleResponse);
                case "HD":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=HD", handleResponse);
                case "MCD":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=MCD", handleResponse);
                case "BA":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=BA", handleResponse);
                case "CAT":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=CAT", handleResponse);
                case "GE":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GE", handleResponse);
                case "F":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=F", handleResponse);
                case "GM":
                    return needle.get("http://download.finance.yahoo.com/d/quotes.csv?s=GM", handleResponse);
                default:
                    return res.status(400).send("Invalid stock symbol");
            }
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;