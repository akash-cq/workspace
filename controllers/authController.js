const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const user = require("../models/user");
const services = require("../services");
const { userService } = require("../services");
const libs = require("../lib");
const { userModel } = require("../models");
const config = require("../config/configVars");

const createSessionObj = (user) => {
  const session = {};
  session.userId = user[userModel.columnName.id];
  session.email = user[userModel.columnName.email];
  session.role = user[userModel.columnName.role];
  session.profilePic = user[userModel.columnName.profilePic];
  session.displayname = user[userModel.columnName.displayname];
  session.status = user[userModel.columnName.status];
  return libs.utils.createSessionObj(session);
};

const checkLoginLimit = async (userId) => {
  try {
    let userInredis = await services.redisService.sessionRedis(
      "smembers",
      `${libs.constants.sessionPrefix}:user:${userId}`
    );
    if (userInredis.length >= 1) {
      return true;
    } else {
      return false;
    }
  } catch (error) {
    console.log(error);
  }
};
async function createTwoFactorToken(user, payload) {
  try {
    const token = Math.floor(1000 + Math.random() * 9000);
    const email = user.email;
    const password = payload.password;
    const rememberMe = payload.rememberMe;

    const emailInstance = services.emailService.CreateEmailFactory(
      {
        email: email,
        Type: libs.constants.emailType.twofactorAuth,
        token: token,
      },
      user
    );
    await emailInstance.sendEmail();

    const jwtToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        rememberMe: rememberMe,
        password: password,
        type: libs.constants.login.twofactor,
      },
      libs.constants.jwtSecret
    );
    await services.redisService.sessionRedis(
      "set",
      `${libs.constants.sessionPrefix}:twofactor:${jwtToken}`,
      token,
      "EX",
      libs.constants.twoFactorAuthExpireTime_Seconds*1000/2 
    );
    return jwtToken;
  } catch (error) {
    console.log(error);
    return error;
  }
}
//TODO Password Validation
/**
 *
 * @param {{email: string, password: string, rememberMe: true}} payload
 * @param {boolean} byPassPasswordCheck
 * Exercise extreme caution when utilizing byPassPasswordCheck, as its misuse can lead to severe security ramifications
 * @returns {Promise<[string, string | undefined]>}
 */
const login = async (payload, byPassPasswordCheck) => {
  const email = payload.email;
  const password = payload.password;
  const rememberMe = payload.rememberMe;
  const user = await userService.getSingleUserFromDb(
    null,
    `where email='${email}'`
  );
  if (!user?.email) {
    throw new Error(`No user found with same email.`);
  }

  if (user?.verification_token !== null) {
    throw new Error(libs.messages.errorMessage.userVerificationRequired);
  }

  if (!byPassPasswordCheck) {
    const isPasswordValid = await libs.utils.checkIfValidEncryption(
      user.password,
      password
    );
    if (!isPasswordValid) {
      throw new Error("Password is not valid");
    }
  }
  const isWant2fa = await checkLoginLimit(user.id);
  if (isWant2fa && payload.type != libs.constants.login.twofactor) {
    const tfToken = await createTwoFactorToken(user, payload);
    // console.log(tfToken);   
    return [null, null, tfToken];
  }

  const sessionObj = createSessionObj(user);
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      sid: sessionObj.sid,
    },
    libs.constants.jwtSecret
  );

  let longTermSessionToken = null;
  if (rememberMe) {
    longTermSessionToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      libs.constants.jwtSecret,
      {
        expiresIn: libs.constants.longTermSessionExpireTime_Seconds,
      }
    );
  }

  await services.redisService.sessionRedis(
    "set",
    `${libs.constants.sessionPrefix}:${sessionObj.sid}`,
    JSON.stringify(sessionObj),
    "EX",
    libs.constants.sessionExpireTime_Seconds
  );
  await services.redisService.sessionRedis(
    "sadd",
    `${libs.constants.sessionPrefix}:user:${user.id}`,
    sessionObj.sid
  );
  await services.redisService.sessionRedis(
    "expire",
    `${libs.constants.sessionPrefix}:user:${user.id}`,
    libs.constants.sessionExpireTime_Seconds
  );
  return [token, longTermSessionToken, null];
};

const signup = async ({ email, password, name }) => {
  const userWithSameEmail = (
    await userService.getUserFormDb(null, `WHERE email='${email}'`)
  )?.[0];
  if (userWithSameEmail) {
    if (userWithSameEmail[userModel.columnName.verification_token] == null) {
      throw new Error(`User with the same email already exists`);
    }
    const verificationToken = config.emailVerificationRequired
      ? crypto.randomBytes(40).toString("hex")
      : null;
    const result = await userService.updateUserDB(
      {
        [userModel.columnName.verification_token]: verificationToken,
      },
      ` WHERE ${userModel.columnName.id} = '${userWithSameEmail.id}'`
    );
    return result?.[0];
  }
  const verificationToken = config.emailVerificationRequired
    ? crypto.randomBytes(40).toString("hex")
    : null;
  console.log(`Verification Token For ${email} = ${verificationToken}`);
  const resultOfUserCreation = await userService.createUserDB({
    [user.columnName.email]: email,
    [user.columnName.displayname]: name,
    [user.columnName.password]: password,
    [user.columnName.verification_token]: verificationToken,
  });
  const result = resultOfUserCreation.rows?.[0];
  if (!result) {
    throw new Error("User Cannot Be Created");
  }
  return result;
};

const verifyAccount = async (token) => {
  const userData = (
    await services.userService.updateUserDB(
      {
        [user.columnName.verification_token]: null,
      },
      `WHERE ${user.columnName.verification_token} = '${token}'`
    )
  )?.[0];
  return userData;
};

const authenticateSession = async function (token) {
  try {
    const userData = jwt.decode(token);
    const { id: userId, sid } = userData;
    if (!sid) throw new Error("Session id is null");
    if (!userId) throw new Error("User id is null");

    const sessionKey = `${libs.constants.sessionPrefix}:${sid}`;
    const sessionStr = await services.redisService.sessionRedis(
      "get",
      sessionKey
    );
    if (!sessionStr) return;

    services.redisService.sessionRedis(
      "expire",
      sessionKey,
      libs.constants.sessionExpireTime_Seconds
    );
    const sessionObj = JSON.parse(sessionStr);
    if (sessionObj && sessionObj.userId == userId)
      return libs.utils.createSessionObj(sessionObj);
    return;
  } catch (error) {
    console.log("Error in authenticateSession. Error = ", error);
    return;
  }
};

module.exports = {
  login,
  signup,
  verifyAccount,
  createSessionObj,
  authenticateSession,
};
