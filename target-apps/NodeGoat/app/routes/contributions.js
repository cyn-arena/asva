const ContributionsDAO = require("../data/contributions-dao").ContributionsDAO;
const {
    environmentalScripts
} = require("../../config/config");

function parseContribution(value) {
    if (typeof value === "number") {
        return Number.isFinite(value) ? value : NaN;
    }

    if (typeof value !== "string") {
        return NaN;
    }

    const trimmed = value.trim();
    if (trimmed.length === 0) {
        return NaN;
    }

    let index = 0;
    let sawDigit = false;
    let sawDecimalPoint = false;
    let sawExponent = false;

    if (trimmed[index] === "+" || trimmed[index] === "-") {
        index += 1;
    }

    for (; index < trimmed.length; index += 1) {
        const character = trimmed[index];

        if (character >= "0" && character <= "9") {
            sawDigit = true;
            continue;
        }

        if (character === "." && !sawDecimalPoint && !sawExponent) {
            sawDecimalPoint = true;
            continue;
        }

        if ((character === "e" || character === "E") && !sawExponent && sawDigit) {
            sawExponent = true;

            if (trimmed[index + 1] === "+" || trimmed[index + 1] === "-") {
                index += 1;
            }

            if (index + 1 >= trimmed.length) {
                return NaN;
            }

            continue;
        }

        return NaN;
    }

    if (!sawDigit) {
        return NaN;
    }

    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : NaN;
}

/* The ContributionsHandler must be constructed with a connected db */
function ContributionsHandler(db) {
    "use strict";

    const contributionsDAO = new ContributionsDAO(db);

    this.displayContributions = (req, res, next) => {
        const {
            userId
        } = req.session;

        contributionsDAO.getByUserId(userId, (error, contrib) => {
            if (error) return next(error);

            contrib.userId = userId; //set for nav menu items
            return res.render("contributions", {
                ...contrib,
                environmentalScripts
            });
        });
    };

    this.handleContributionsUpdate = (req, res, next) => {

        const preTax = parseContribution(req.body.preTax);
        const afterTax = parseContribution(req.body.afterTax);
        const roth = parseContribution(req.body.roth);

        const {
            userId
        } = req.session;

        //validate contributions
        const validations = [Number.isNaN(preTax), Number.isNaN(afterTax), Number.isNaN(roth), preTax < 0, afterTax < 0, roth < 0];
        const isInvalid = validations.some(validation => validation);
        if (isInvalid) {
            return res.render("contributions", {
                updateError: "Invalid contribution percentages",
                userId,
                environmentalScripts
            });
        }
        // Prevent more than 30% contributions
        if (preTax + afterTax + roth > 30) {
            return res.render("contributions", {
                updateError: "Contribution percentages cannot exceed 30 %",
                userId,
                environmentalScripts
            });
        }

        contributionsDAO.update(userId, preTax, afterTax, roth, (err, contributions) => {

            if (err) return next(err);

            contributions.updateSuccess = true;
            return res.render("contributions", {
                ...contributions,
                environmentalScripts
            });
        });

    };

}

module.exports = ContributionsHandler;