const express = require("express");
const viewsController = require("../controllers/viewsController");
const authController = require("../controllers/authController");
const bookingController = require("../controllers/bookingController");

const router = express.Router();

router.get(
  "/",
  bookingController.createBookingCheckout,
  authController.isLoggenIn,
  viewsController.getOverview
);
router.get("/tour/:slug", authController.isLoggenIn, viewsController.getTour);
router.get("/login", authController.isLoggenIn, viewsController.getLoginForm);
router.get("/me", viewsController.getAccount);
router.get("/my-tours", authController.protect, viewsController.getMyTours);

router.post(
  "/submit-user-data",
  authController.protect,
  viewsController.updateUserData
);

module.exports = router;
