const express = require("express");
const viewsController = require("../controllers/viewsController");
const authController = require("../controllers/authController");

const router = express.Router();

router.get("/", authController.isLoggenIn, viewsController.getOverview);
router.get("/tour/:slug", authController.isLoggenIn, viewsController.getTour);
router.get("/login", authController.isLoggenIn, viewsController.getLoginForm);
router.get("/me", viewsController.getAccount);

router.post(
  "/submit-user-data",
  authController.protect,
  viewsController.updateUserData
);

module.exports = router;
