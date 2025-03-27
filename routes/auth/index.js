const router = require("express").Router();
const jwt = require("jsonwebtoken");
const utils = require("../../utils");

const configVars = require("../../config/configVars");
const controllers = require("../../controllers");
const emailService = require("../../services/emailService");
const libs = require("../../lib");
const middlewares = require("../../middlewares");
const config = require("../../config/configVars");
const services = require("../../services");

router.post("/login", async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: `Invalid Payload email and password required.` });
    }
    if (!libs.regex.email.test(email)) {
      return res.status(400).json({ error: `Email is not valid.` });
    }
    const [token, longTermToken, tfToken] =
      await controllers.authController.login({
        email,
        password,
        rememberMe,
        type: libs.constants.login.normal,
      });
    if (tfToken) {
      res.cookie("tjwt", tfToken, {
        ...configVars.sessionCookieConfig,
        maxAge: libs.constants.twoFactorAuthExpireTime_Seconds * 1000,
      });
      return res.status(403).json({
        error:
          "2 factor Authentication is enabled please check your email for OTP",
      });
    }
    if (longTermToken) {
      res.cookie("ljwt", longTermToken, {
        ...configVars.sessionCookieConfig,
        maxAge: libs.constants.longTermSessionExpireTime_Seconds * 1000,
      });
    }
    res.cookie("jwt", token, configVars.sessionCookieConfig);
    return res.json({ status: "Success" });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message });
  }
});

router.post("/signup", async (req, res) => {
  try {
    const { email, password, name, referToken } = req.body;
    if (!email || !password || !name) {
      return res
        .status(403)
        .json({ error: `Invalid Payload name, email and passowrd required.` });
    }

    if (!libs.regex.email.test(email)) {
      return res.status(400).json({ error: `Email is not valid.` });
    }
    if (!libs.regex.password.test(password)) {
      return res.status(400).json({ error: `Password is not valid.` });
    }
    const encPassword = await libs.utils.encryptString(password);
    const user = await controllers.authController.signup({
      email,
      password: encPassword,
      name,
    });
    // name, userId, type = constants.workSpaceTypes.basicType, courseId
    if (config.createDefaultWorkspace) {
      const workspace = await controllers.workspaceController.createWorkSpace({
        name: "General",
        type: libs.constants.workSpaceTypes.basicType,
        userId: user.id,
      });
      await controllers.channelController.createChannel({
        workspaceId: workspace.workspaceId,
        userId: user.id,
        name: "General",
      });
    }
    const token = user.verification_token;
    if (config.emailVerificationRequired) {
      const emailInstance = emailService.CreateEmailFactory(
        { email: email, Type: libs.constants.emailType.NewUser, token: token },
        user
      );
      await emailInstance.sendEmail();
    }
    if (referToken) {
      const data = await utils.jwtToken.verifyToken(
        referToken,
        process.env.JWT_SECRET
      );
      if (data.email === email) {
        data.userId = user.id;
        const obj = await controllers.channelController.addUserToChannel(data);
      }
    }
    return res.json({ status: libs.constants.statusToNumber.success });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message });
  }
});

router.get("/verifyEmail", async (req, res) => {
  try {
    const token = req.query?.token ?? req.body?.token;
    if (!token)
      return res.status(400).json({
        error: libs.messages.errorMessage.verificationTokenNotPresent,
      });
    const user = await controllers.authController.verifyAccount(token);
    if (!user?.email)
      throw new Error(libs.messages.errorMessage.tokenIsNotValid);
    const url = new URL(configVars.frontendURL);
    url.searchParams.set("message", "Account verified successfully!");
    url.searchParams.set(
      "messageType",
      libs.constants.queryParamsMessageType.success
    );
    return res.redirect(url.toString());
  } catch (error) {
    const url = new URL(configVars.frontendURL);
    url.searchParams.set("message", error?.message ?? error);
    url.searchParams.set(
      "messageType",
      libs.constants.queryParamsMessageType.error
    );
    return res.redirect(url.toString());
  }
});

router.post("/forgot", async (req, res) => {
  try {
    const { email, reCaptcha } = req.body;
    if (!email) {
      throw new Error(libs.messages.errorMessage.emailNotProvided);
    }
    if (!reCaptcha) {
      throw new Error(libs.messages.errorMessage.reCaptchaError);
    }
    await libs.utils.validateRecaptcha(reCaptcha);
    await controllers.userController.forgotPassword(email);
    return res.json({ status: libs.constants.statusToNumber.success });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message ?? error });
  }
});

router.get(
  ["/validatePasswordResetToken/:token", "/validatePasswordResetToken"],
  async (req, res) => {
    try {
      const token = req.params.token ?? req.query.token;
      if (!token)
        throw new Error(libs.messages.errorMessage.resetTokenNotPresent);
      const userId =
        await controllers.userController.validateResetPasswordToken(token);
      return res.json({ status: libs.constants.statusToNumber.success });
    } catch (error) {
      console.log(error);
      return res.json({ error: "Token is not valid." });
    }
  }
);

router.post("/resetPassword", async (req, res) => {
  try {
    const { password, token } = req.body;
    if (!password || !token)
      throw new Error(libs.messages.errorMessage.payloadIsNotValid);
    if (!libs.regex.password.test(password))
      throw new Error(libs.messages.errorMessage.passwordIsNotValid);
    const userId = await controllers.userController.validateResetPasswordToken(
      token
    );
    if (!userId) throw new Error(libs.messages.errorMessage.linkExpired);
    const encPassword = await libs.utils.encryptString(password);
    await controllers.userController.updateUserProfile(userId, {
      password: encPassword,
      passwordResetToken: null,
    });
    return res.json({ status: libs.constants.statusToNumber.success });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message ?? error });
  }
});

router.post("/resetPassword", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token) throw new Error(libs.messages.errorMessage.tokenIsNotValid);
    if (!password)
      throw new Error(libs.messages.errorMessage.passwordIsNotValid);
    if (!libs.regex.password.test(password))
      throw new Error(libs.messages.errorMessage.passwordIsNotValid);
    await controllers.authController.updatePassword({ token, password });
    return res.json({ status: libs.constants.statusToNumber.success });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message ?? error });
  }
});

router.post("/twofactor", async (req, res) => {
  try {
    const { twofactor } = req.body;
    if (!twofactor) throw new Error("2 factor authentication code is required");
    const Ntoken = req.cookies.tjwt;
    if (!Ntoken) throw new Error("session is expired");
    const decode = jwt.decode(Ntoken);
    if (!decode) throw new Error("Token is not valid");
    const { email, password, rememberMe, type } = decode;
    const otp = await services.redisService.sessionRedis(
      "get",
      `${libs.constants.sessionPrefix}:twofactor:${Ntoken}`
    );
    await services.redisService.sessionRedis(
      "del",
      `${libs.constants.sessionPrefix}:twofactor:${Ntoken}`
    );
    if (type !== libs.constants.login.twofactor)
      throw new Error("Invalid token type");
    if (otp != twofactor)
      throw new Error("Invalid 2 factor authentication code");

    const [token, longTermToken, tfToken] =
      await controllers.authController.login({
        email,
        password,
        rememberMe,
        type: libs.constants.login.twofactor,
      });
    if (token === null) {
      throw new Error("something wrong with token");
    }
    if (longTermToken) {
      res.cookie("ljwt", longTermToken, {
        ...configVars.sessionCookieConfig,
        maxAge: libs.constants.longTermSessionExpireTime_Seconds,
      });
    }
    res.cookie("jwt", token, configVars.sessionCookieConfig);
    res.clearCookie("tjwt");
    return res.json({ status: "Success" });
  } catch (error) {
    console.log(error);
    return res.json({ error: error?.message });
  }
});

router.get("/twofactorResend", async (req, res) => {
  try {
    const jwtToken = req.cookies.tjwt;
    if (!jwtToken) throw new Error("session is expire");
    const decode = jwt.decode(jwtToken);
    if (!decode) throw new Error("Token is not valid");
    const { email } = decode;
    const token = Math.floor(1000 + Math.random() * 9000);

    await services.redisService.sessionRedis(
      "set",
      `${libs.constants.sessionPrefix}:twofactor:${jwtToken}`,
      token,
      "EX",
      (libs.constants.twoFactorAuthExpireTime_Seconds * 1000) / 2
    );
    const emailInstance = emailService.CreateEmailFactory({
      email: email,
      Type: libs.constants.emailType.twofactorAuth,
      token: token,
    });
    await emailInstance.sendEmail();

    return res.json({ status: "Success" });
  } catch (err) {
    console.log(err);
    return res.json({ error: err?.message });
  }
});
router.all(
  "/logout",
  middlewares.session.checkLogin(true),
  async (req, res) => {
    try {
      const { sid } = req.session;
      await libs.utils.deleteSession(sid);
      res.clearCookie("jwt", configVars.sessionCookieConfig);
      res.clearCookie("ljwt", {
        ...configVars.sessionCookieConfig,
      });
      return res.json({ msg: `Session logged out` });
    } catch (error) {
      return res.json({ error: error?.message ?? error });
    }
  }
);

module.exports = router;
