const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
const passwordRegex =/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!/@;<#$%^&>?/?>.,\\|{}[\]_-]).{8,32}$/;
const nameRegex = /^[a-zA-Z0-9-_ ]{1,50}$/;
const otpRegex = /^\d{4}$/;
const lengthRegex = (length) => {
    return new RegExp(`^.{0,${length}}$`);
}

module.exports = {
  email: emailRegex,
  password: passwordRegex,
  name: nameRegex,
  channelRegex: lengthRegex(30),
  otpRegex: otpRegex,
};