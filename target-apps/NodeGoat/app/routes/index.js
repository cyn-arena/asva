const SessionHandler = require("./session");
const ProfileHandler = require("./profile");
const BenefitsHandler = require("./benefits");
const ContributionsHandler = require("./contributions");
const AllocationsHandler = require("./allocations");
const MemosHandler = require("./memos");
const ResearchHandler = require("./research");
const tutorialRouter = require("./tutorial");
const ErrorHandler = require("./error").errorHandler;

const index = (app, db) => {

    "use strict";

    const sessionHandler = new SessionHandler(db);
    const profileHandler = new ProfileHandler(db);
    const benefitsHandler = new BenefitsHandler(db);
    const contributionsHandler = new ContributionsHandler(db);
    const allocationsHandler = new AllocationsHandler(db);
    const memosHandler = new MemosHandler(db);
    const researchHandler = new ResearchHandler(db);

    const isLoggedIn = sessionHandler.isLoggedInMiddleware;

    const isAdmin = sessionHandler.isAdminUserMiddleware;

    app.get("/", sessionHandler.displayWelcomePage);

    app.get("/login", sessionHandler.displayLoginPage);
    app.post("/login", sessionHandler.handleLoginRequest);

    app.get("/signup", sessionHandler.displaySignupPage);
    app.post("/signup", sessionHandler.handleSignup);

    app.get("/logout", sessionHandler.displayLogoutPage);

    app.get("/dashboard", isLoggedIn, sessionHandler.displayWelcomePage);

    app.get("/profile", isLoggedIn, profileHandler.displayProfile);
    app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);

    app.get("/contributions", isLoggedIn, contributionsHandler.displayContributions);
    app.post("/contributions", isLoggedIn, contributionsHandler.handleContributionsUpdate);

    app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
    app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);

    app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);

    app.get("/memos", isLoggedIn, memosHandler.displayMemos);
    app.post("/memos", isLoggedIn, memosHandler.addMemos);

    app.get("/learn", isLoggedIn, (req, res) => {
        const requestedUrl = req.query.url;

        if (requestedUrl === "/research" || requestedUrl === "research") {
            return res.redirect(302, "/research");
        }

        if (requestedUrl === "https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras") {
            return res.redirect(302, "https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras");
        }

        return res.redirect(302, "/tutorial");
    });

    app.get("/research", isLoggedIn, researchHandler.displayResearch);

    app.use("/tutorial", tutorialRouter);

    app.use(ErrorHandler);
};

module.exports = index;