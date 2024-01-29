export default () => ({
  port: parseInt(process.env.PORT) || 5000,
  DATABASE_URL: process.env.MONGODB_URI,

  SECRET: process.env.JWT_SECRET,
  jwt_confg: {
    secret: process.env.JWT_SECRET,
    signOptions: { expiresIn: '1d' },
  },

  APP_URL: process.env.APP_URL,
  EMAIL_FROM: process.env.EMAIL_FROM,
  MAIL_HOST: process.env.EMAIL_HOST,
  MAIL_PORT: process.env.EMAIL_PORT,
  MAIL_USER: process.env.EMAIL_USER,
  MAIL_PASS: process.env.EMAIL_PASS,
});
